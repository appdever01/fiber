package cache

import (
	"container/list"
	"context"
	"errors"
	"math"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/internal/fieldname"
	"github.com/gofiber/fiber/v3/internal/headerlist"
	"github.com/gofiber/fiber/v3/internal/headerlookup"
	"github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/utils/v2"
)

// credentialHeaders carry nothing but a credential. No other name counts.
var credentialHeaders = []string{fiber.HeaderAuthorization, fiber.HeaderCookie, fiber.HeaderProxyAuthorization, "X-API-Key", "X-Auth-Token", "X-Access-Token"}

// customKeyCredentialHeaders are those of credentialHeaders an opaque custom key can be taken to
// hold. Cookie is not one: it mostly carries cookies that are no credential.
var customKeyCredentialHeaders = slices.DeleteFunc(slices.Clone(credentialHeaders), func(name string) bool {
	return name == fiber.HeaderCookie
})

// carriesCredential reports whether the header is in credentialHeaders or KeyCredentialHeaders.
func (cfg *Config) carriesCredential(name string) bool {
	return fieldname.ContainsFold(credentialHeaders, name) || fieldname.ContainsFold(cfg.KeyCredentialHeaders, name)
}

// appendCredentials appends to dst those of names that carry a credential.
func (cfg *Config) appendCredentials(dst, names []string) []string {
	for _, name := range names {
		if cfg.carriesCredential(name) {
			dst = append(dst, name)
		}
	}
	return dst
}

// varyListsCredential reports whether a Vary value names a credential header, without allocating.
func (cfg *Config) varyListsCredential(vary []byte) bool {
	for name := range headerlist.All(utils.UnsafeString(vary)) {
		if cfg.carriesCredential(name) {
			return true
		}
	}
	return false
}

// holdsCredentialResponse reports whether the entry found, stored with this Vary, can hold
// one client's response: the key is partitioned by a credential or the Vary names one. A
// custom KeyGenerator is opaque, so it counts when the request sends a declared header.
func (cfg *Config) holdsCredentialResponse(c fiber.Ctx, vary []byte) bool {
	// Config checks first: cheaper than walking Vary or reading headers.
	if len(cfg.KeyCookies) > 0 || (cfg.usesDefaultKeyGenerator && len(cfg.credentialKeyHeaders) > 0) {
		return true
	}
	return cfg.varyListsCredential(vary) || (!cfg.usesDefaultKeyGenerator && hasHeaderValue(c, cfg.credentialKeyHeaders))
}

// refusesCredential reports whether status is the origin refusing the credential (407 for a
// proxy's). Unlike a 5xx, which RFC 9111 §4.3.3 lets a cache ride out, it is a verdict.
func refusesCredential(status int) bool {
	return status == fiber.StatusUnauthorized ||
		status == fiber.StatusForbidden ||
		status == fiber.StatusProxyAuthRequired
}

// errorRefusesCredential is refusesCredential for a returned *fiber.Error, wrapped or not.
func errorRefusesCredential(err error) bool {
	var fiberErr *fiber.Error
	// A nil *fiber.Error held in an error matches errors.As and has no Code.
	return errors.As(err, &fiberErr) && fiberErr != nil && refusesCredential(fiberErr.Code)
}

// credentialScope is how far a refusal reaches.
type credentialScope struct {
	entry bool // the refusal ends the entry the request found
	keyed bool // the key holds the credential, so the Vary manifest is its own too
}

// scopeOf says how far a refusal reaches, read before the handler runs. A refusal is a verdict on
// a credential, so it ends the entry found only when that is the credential's own: the key holds
// it, or the Vary the entry was stored with names a header that carries it. A custom
// KeyGenerator's key is opaque, so there a credential header the request sends counts too.
func (cfg *Config) scopeOf(c fiber.Ctx, varyNames []string, hasAuthorization bool) credentialScope { //nolint:revive // flag-parameter: a property of the request, not a mode of operation
	keyed := hasAuthorization || cfg.keyHoldsRequestCredential(c)
	return credentialScope{
		keyed: keyed,
		entry: keyed || cfg.varyHoldsRequestCredential(c, varyNames) || (!cfg.usesDefaultKeyGenerator && cfg.requestCarriesCredential(c)),
	}
}

// varyHoldsRequestCredential reports whether an entry stored under a Vary that names credential
// headers was selected by one the request sends.
func (cfg *Config) varyHoldsRequestCredential(c fiber.Ctx, varyNames []string) bool {
	var named [defaultVaryNames]string
	credentials := cfg.appendCredentials(named[:0], varyNames)
	return len(credentials) > 0 && hasHeaderValue(c, credentials)
}

const (
	minRefusalRecords       = 1024  // the fewest refusal records an in-memory store makes room for
	unlimitedRefusalRecords = 16384 // how many it keeps when MaxBytes sets no limit
	refusalRecordSize       = 256   // what one record counts as against MaxBytes, which sizes the limit
)

// refusalMarker tells the instances sharing an external Storage that a record may exist in it, so a
// hit looks for its record only then.
const refusalMarker = cacheKeyVersion + "|refused"

// refusalLimit is how many refusal records an in-memory store keeps, the oldest going first.
func (cfg *Config) refusalLimit() int {
	if cfg.refusalRecordLimit > 0 {
		return cfg.refusalRecordLimit
	}
	if cfg.MaxBytes == 0 {
		return unlimitedRefusalRecords
	}
	return int(min(max(cfg.MaxBytes/refusalRecordSize, minRefusalRecords), math.MaxInt32))
}

// refusalRecords keeps the records of refused credentials. An in-memory store holds no more than
// its limit, so refusing many credentials cannot grow it unbounded. An external Storage expires its
// records itself, and forgetting a live one would lift its protection.
type refusalRecords struct {
	cfg       *Config
	m         *manager
	keys      keyLog
	family    Config        // cfg with the credential headers alone, so a record reaches every variant of the URL
	until     atomic.Uint64 // the second from which no record written here is live
	saturated atomic.Uint64 // the second until which a record dropped while live could have applied
	seen      atomic.Uint64 // the second the marker was last read
	open      atomic.Bool   // whether it was there
}

func newRefusalRecords(cfg *Config, m *manager) *refusalRecords {
	r := &refusalRecords{cfg: cfg, family: *cfg, m: m}
	r.family.KeyHeaders = cfg.credentialKeyHeaders
	if cfg.Storage == nil {
		r.keys.limit = cfg.refusalLimit()
	}
	return r
}

// key is where the refusal of the request's credential is recorded: under the key without its
// other dimensions, so one record reaches every variant of the URL, and a digest of the headers the
// Vary selects by. It is empty when there is nothing to record: the key holds no credential the
// request sends, and the entry was not selected by one.
func (r *refusalRecords) key(c fiber.Ctx, base string, varyNames []string, hasAuthorization bool) string { //nolint:revive // flag-parameter: a property of the request, not a mode of operation
	cfg := r.cfg
	var named [defaultVaryNames]string
	varied := cfg.appendCredentials(named[:0], varyNames)
	if !cfg.usesDefaultKeyGenerator {
		if hasAuthorization {
			return "" // in every key, so the manifest the refusal drops is the credential's own
		}
		// A custom key is opaque: assume the declared headers are in it.
		varied = append(varied, cfg.KeyCredentialHeaders...)
		slices.Sort(varied)
		varied = slices.Compact(varied)
	}
	selected := len(varied) > 0 && hasHeaderValue(c, varied)
	held := cfg.usesDefaultKeyGenerator && (hasAuthorization || cfg.keyHoldsRequestCredential(c))
	if !selected && !held {
		return ""
	}

	canonical := headerlookup.Canonical(c)
	bufPtr := acquireKeyBuffer()
	buf := (*bufPtr)[:0]
	if cfg.usesDefaultKeyGenerator {
		buf = append(buf, cacheKeyVersion...)
		buf = append(buf, '|')
		buf = append(buf, c.Method()...)
		buf = append(buf, '|')
		buf = appendDefaultKey(buf, c, &r.family)
		if hasAuthorization {
			buf = append(buf, "|auth="...)
			buf = appendAuthHash(buf, fieldname.Lines(&c.Request().Header, fiber.HeaderAuthorization, canonical))
		}
	} else {
		buf = append(buf, base...)
	}
	buf = append(buf, "|refused"...)
	if selected {
		buf = appendVaryKey(buf, varied, &c.Request().Header, canonical)
	}
	key := string(buf)
	releaseKeyBuffer(bufPtr, buf)
	return key
}

// mayHold reports whether a record can exist for a hit to find. The in-memory store holds only
// those written here, until they expire by its clock. An external Storage may hold ones another
// instance wrote, which announces them with a marker read at most once a second.
func (r *refusalRecords) mayHold(ctx context.Context) bool {
	now := uint64(utils.Timestamp())
	if now < r.until.Load() {
		return true
	}
	if r.cfg.Storage == nil {
		return false
	}
	if r.seen.Load() == now {
		return r.open.Load()
	}
	_, err := r.m.getRaw(ctx, refusalMarker)
	if err != nil && !errors.Is(err, errCacheMiss) {
		log.Warnf("cache: failed to read the marker of refusal records: %v", err)
	}
	open := !errors.Is(err, errCacheMiss)
	r.open.Store(open)
	r.seen.Store(now)
	return open
}

// refused reports whether a refusal was recorded under key, which keeps the credential's
// other variants from being served. A storage that cannot answer counts as one, and so does
// every key while a record that was dropped live could still have applied to it.
func (r *refusalRecords) refused(ctx context.Context, key string) bool {
	if uint64(utils.Timestamp()) < r.saturated.Load() {
		return true
	}
	_, err := r.m.getRaw(ctx, key)
	if err == nil {
		return true
	}
	if errors.Is(err, errCacheMiss) {
		return false
	}
	log.Warnf("cache: failed to read the record of a refused credential: %v", err)
	return true
}

// record keeps the refusal under key for Expiration, or until entryExp (unix seconds, 0 if
// unknown) when later.
func (r *refusalRecords) record(ctx context.Context, key string, entryExp uint64) {
	retention := r.cfg.Expiration
	if now := safeUnixSeconds(r.cfg.now()); entryExp > now {
		retention = max(retention, secondsToDuration(entryExp-now))
	}
	// Raised before the write: +1 for the store's rounding, +1 for a tick between its clock
	// read and ours.
	end := uint64(utils.Timestamp()) + uint64(retention.Seconds()) + 2
	raise(&r.until, end)
	if err := r.m.setRaw(ctx, key, []byte{1}, retention); err != nil {
		log.Warnf("cache: failed to record the refusal of a credential: %v", err)
		return
	}
	if r.cfg.Storage != nil {
		// Announced to the other instances for as long as the longest record written here.
		if err := r.m.setRaw(ctx, refusalMarker, []byte{1}, secondsToDuration(r.until.Load()-uint64(utils.Timestamp()))); err != nil {
			log.Warnf("cache: failed to announce the record of a refused credential: %v", err)
		}
	}
	if oldest := r.keys.add(key, end); oldest.key != "" {
		// Dropped to bound the store. If it was still live, a hit it would have refused is served
		// unless the cache fails closed until the record would have lapsed.
		if oldest.until > uint64(utils.Timestamp()) {
			raise(&r.saturated, oldest.until)
		}
		if err := r.m.del(ctx, oldest.key); err != nil {
			log.Warnf("cache: failed to drop the oldest record of a refused credential: %v", err)
		}
	}
}

// raise lifts a to v if it is lower.
func raise(a *atomic.Uint64, v uint64) {
	for old := a.Load(); v > old; old = a.Load() {
		if a.CompareAndSwap(old, v) {
			return
		}
	}
}

// forget drops the record once the origin accepts the credential again.
func (r *refusalRecords) forget(ctx context.Context, key string) {
	r.keys.remove(key)
	if err := r.m.del(ctx, key); err != nil {
		log.Warnf("cache: failed to clear the record of a refused credential: %v", err)
	}
}

// loggedKey is a key and the second it lapses.
type loggedKey struct {
	key   string
	until uint64
}

// keyLog remembers up to limit keys, forgetting the oldest first; with no limit it keeps none.
type keyLog struct {
	items map[string]*list.Element
	order list.List
	mu    sync.Mutex
	limit int
}

// add remembers key until the second given, and returns the oldest key it had to forget to stay
// within its limit, which is empty when it forgot none.
func (l *keyLog) add(key string, until uint64) loggedKey {
	if l.limit == 0 {
		return loggedKey{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if element, ok := l.items[key]; ok {
		if logged, ok := element.Value.(loggedKey); ok {
			element.Value = loggedKey{key: key, until: max(logged.until, until)}
		}
		l.order.MoveToBack(element)
		return loggedKey{}
	}
	if l.items == nil {
		l.items = make(map[string]*list.Element)
	}
	l.items[key] = l.order.PushBack(loggedKey{key: key, until: until})
	if l.order.Len() <= l.limit {
		return loggedKey{}
	}
	oldest, ok := l.order.Remove(l.order.Front()).(loggedKey)
	if !ok {
		return loggedKey{}
	}
	delete(l.items, oldest.key)
	return oldest
}

// remove forgets key.
func (l *keyLog) remove(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if element, ok := l.items[key]; ok {
		l.order.Remove(element)
		delete(l.items, key)
	}
}

// keyHoldsRequestCredential reports whether the default key holds a credential the request
// carries (a KeyCookies cookie or a credential header); a custom key is opaque, so holds none.
func (cfg *Config) keyHoldsRequestCredential(c fiber.Ctx) bool {
	if !cfg.usesDefaultKeyGenerator {
		return false
	}
	for _, name := range cfg.KeyCookies {
		if c.Cookies(name) != "" {
			return true
		}
	}
	return hasHeaderValue(c, cfg.credentialKeyHeaders)
}

// requestCarriesCredential reports whether the request sends a credential header an opaque custom
// key can be taken to hold: a declared one, or one of customKeyCredentialHeaders.
func (cfg *Config) requestCarriesCredential(c fiber.Ctx) bool {
	return hasHeaderValue(c, customKeyCredentialHeaders) || hasHeaderValue(c, cfg.KeyCredentialHeaders)
}

// hasHeaderValue reports whether the request sends a value for any of the headers.
func hasHeaderValue(c fiber.Ctx, names []string) bool {
	canonical := headerlookup.Canonical(c)
	for _, name := range names {
		if utils.EqualFold(name, fiber.HeaderCookie) {
			// Walk fasthttp's cookie store: building the Cookie line allocates.
			for range c.Request().Header.Cookies() {
				return true
			}
			continue
		}
		if len(fieldname.First(&c.Request().Header, name, canonical)) > 0 {
			return true
		}
	}
	return false
}
