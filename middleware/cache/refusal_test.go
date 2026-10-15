package cache

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// credentialPartition is a way the cache can tell sessions apart, and how the fixture sends and reads one.
type credentialPartition struct {
	configure    func(*Config)               // makes the cache tell sessions apart
	send         func(*http.Request, string) // puts a session on a request
	read         func(fiber.Ctx) string      // takes it off again
	vary         string                      // the Vary the app adds, if any
	cacheControl string                      // the Cache-Control the app adds, if any
}

func sendCookie(req *http.Request, session string) {
	req.Header.Set(fiber.HeaderCookie, "session="+session)
}

func readCookie(c fiber.Ctx) string { return c.Cookies("session") }

func sendBearer(req *http.Request, session string) {
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+session)
}

func readBearer(c fiber.Ctx) string {
	return strings.TrimPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
}

// headerPartition carries the session in the named request header.
func headerPartition(name string, configure func(*Config)) credentialPartition {
	return credentialPartition{
		configure: configure,
		send:      func(req *http.Request, session string) { req.Header.Set(name, session) },
		read:      func(c fiber.Ctx) string { return c.Get(name) },
	}
}

var credentialPartitions = map[string]credentialPartition{
	"keyCookies": {
		configure: func(cfg *Config) { cfg.KeyCookies = []string{"session"} },
		send:      sendCookie,
		read:      readCookie,
	},
	"varyCookie": {send: sendCookie, read: readCookie, vary: fiber.HeaderCookie},
	"authorization": {
		send: sendBearer,
		read: readBearer,
		// Stored only when the response says a shared cache may.
		cacheControl: "public, max-age=60",
	},
	// An API key, which the cache takes for a credential by name.
	"apiKey": headerPartition("X-Api-Key", func(cfg *Config) { cfg.KeyHeaders = []string{"X-Api-Key"} }),
	// A header of the app's own, declared in KeyCredentialHeaders.
	"credentialHeader": headerPartition("X-Company-Token", func(cfg *Config) { cfg.KeyCredentialHeaders = []string{"X-Company-Token"} }),
	// Varies on a header the cache recognizes, whatever the key is built from.
	"varyApiKey": func() credentialPartition {
		p := headerPartition("X-Api-Key", nil)
		p.vary = "X-Api-Key"
		return p
	}(),
	// A custom key built from a declared credential header.
	"customKey": headerPartition("X-Company-Token", func(cfg *Config) {
		cfg.KeyCredentialHeaders = []string{"X-Company-Token"}
		cfg.KeyGenerator = func(c fiber.Ctx) string { return c.Path() + "|" + c.Get("X-Company-Token") }
	}),
	// Headers nothing marks as a credential.
	"tenant":       headerPartition("X-Tenant", func(cfg *Config) { cfg.KeyHeaders = []string{"X-Tenant"} }),
	"customHeader": headerPartition("X-Session", func(cfg *Config) { cfg.KeyHeaders = []string{"X-Session"} }),
	"customVary": func() credentialPartition {
		p := headerPartition("X-Session", nil)
		p.vary = "X-Session"
		return p
	}(),
}

// credentialFixture is an app behind the cache that answers per session: valid sessions
// get a body naming them and their X-Variant, any other is handed to refuse.
type credentialFixture struct {
	app           *fiber.App
	t             *testing.T
	probe         *accountingProbe
	ended         sync.Map
	variantHeader string
	partition     credentialPartition
	calls         atomic.Int32
	noStore       atomic.Bool // the answer to a valid session says not to keep it
}

type credentialOptions struct {
	custom fiber.Storage         // used instead of storage when set
	refuse func(fiber.Ctx) error // the answer to a session that is not valid, a bare 401 when nil
	// clock and expiration push an entry past its lifetime while storage still holds it.
	clock *testClock
	// beforeRefusal runs in the origin before it refuses a session, as a concurrent request would.
	beforeRefusal func(*credentialFixture)
	partition     string   // a key of credentialPartitions
	storage       string   // memory or external
	vary          string   // a Vary the served answer carries besides the partition's
	variantHeader string   // the header a variant is sent in, X-Variant when empty
	valid         []string // the sessions the app answers, "a" and "b" when nil
	expiration    time.Duration
	recordCap     int  // how many refusal records an in-memory cache keeps, derived from MaxBytes when zero
	allowStale    bool // AllowStaleCredentialResponses
	// invalidateEnded has CacheInvalidator report the sessions the app has ended.
	invalidateEnded bool
}

// The axes the refusal scenarios run over: how a client reloads, and what refuses it.
var (
	reloadForms     = []string{"max-age=0", "no-cache"}
	refusalStatuses = []int{fiber.StatusUnauthorized, fiber.StatusForbidden, fiber.StatusProxyAuthRequired}
)

func newCredentialFixture(t *testing.T, opts *credentialOptions) *credentialFixture {
	t.Helper()

	partition, ok := credentialPartitions[opts.partition]
	require.True(t, ok, "unknown partition %q", opts.partition)

	valid := opts.valid
	if valid == nil {
		valid = []string{"a", "b"}
	}
	refuse := opts.refuse
	if refuse == nil {
		refuse = refusal(fiber.StatusUnauthorized, "bare")
	}

	f := &credentialFixture{t: t, probe: &accountingProbe{}, partition: partition, variantHeader: opts.variantHeader}
	if f.variantHeader == "" {
		f.variantHeader = "X-Variant"
	}
	// A byte limit turns on the heap accounting a purge has to keep honest.
	cfg := Config{MaxBytes: 1 << 20, accounting: f.probe.record, Expiration: opts.expiration, AllowStaleCredentialResponses: opts.allowStale, refusalRecordLimit: opts.recordCap}
	if opts.clock != nil {
		cfg.clock = opts.clock.Now
	}
	if partition.configure != nil {
		partition.configure(&cfg)
	}
	cfg.Storage = opts.custom
	if cfg.Storage == nil {
		cfg.Storage = storageOf(opts.storage)
	}
	if opts.invalidateEnded {
		cfg.CacheInvalidator = func(c fiber.Ctx) bool {
			_, ended := f.ended.Load(partition.read(c))
			return ended
		}
	}

	f.app = fiber.New()
	f.app.Use(New(cfg))
	f.app.Get("/account", func(c fiber.Ctx) error {
		f.calls.Add(1)
		session := partition.read(c)
		if _, ended := f.ended.Load(session); ended || !slices.Contains(valid, session) {
			if opts.beforeRefusal != nil {
				opts.beforeRefusal(f)
			}
			return refuse(c)
		}

		vary := slices.DeleteFunc([]string{partition.vary, opts.vary}, func(name string) bool { return name == "" })
		if len(vary) > 0 {
			c.Set(fiber.HeaderVary, strings.Join(vary, ", "))
		}
		if partition.cacheControl != "" {
			c.Set(fiber.HeaderCacheControl, partition.cacheControl)
		}
		if f.noStore.Load() {
			c.Set(fiber.HeaderCacheControl, "no-store")
		}
		return c.SendString(accountBody(session, c.Get(f.variantHeader)))
	})
	return f
}

// get asks for the account as session, sent the way the partition carries it; an empty session sends nothing.
func (f *credentialFixture) get(session, variant, cacheControl string) reply {
	f.t.Helper()

	req := httptest.NewRequest(fiber.MethodGet, "/account", http.NoBody)
	if session != "" {
		f.partition.send(req, session)
	}
	if variant != "" {
		req.Header.Set(f.variantHeader, variant)
	}
	if cacheControl != "" {
		req.Header.Set(fiber.HeaderCacheControl, cacheControl)
	}
	return doRequest(f.t, f.app, req)
}

// requireHit asserts the session is answered from the cache with its own data.
func (f *credentialFixture) requireHit(session, variant string) {
	f.t.Helper()

	got := f.get(session, variant, "")
	require.Equal(f.t, fiber.StatusOK, got.status)
	require.Equal(f.t, accountBody(session, variant), got.body)
	require.Equal(f.t, cacheHit, got.cache)
}

// warm sends each session's request for each variant and asserts every one reached the origin.
func (f *credentialFixture) warm(sessions []string, variants ...string) {
	f.t.Helper()

	if len(variants) == 0 {
		variants = []string{""}
	}
	for _, session := range sessions {
		for _, variant := range variants {
			got := f.get(session, variant, "")
			require.Equal(f.t, fiber.StatusOK, got.status)
			require.Equal(f.t, accountBody(session, variant), got.body)
			require.Equal(f.t, cacheMiss, got.cache)
		}
	}
}

// requireRefused asserts that session "a", which the app has ended, reached the origin and was
// refused with status, and returns the reply.
func (f *credentialFixture) requireRefused(status int, variant, cacheControl string) reply {
	f.t.Helper()

	return f.requireRefusedAs(status, "a", variant, cacheControl)
}

// requireRefusedAs is requireRefused for another session.
func (f *credentialFixture) requireRefusedAs(status int, session, variant, cacheControl string) reply {
	f.t.Helper()

	calls := f.calls.Load()
	got := f.get(session, variant, cacheControl)
	require.Equal(f.t, status, got.status, "a refused credential was answered from the cache")
	require.NotContains(f.t, got.body, "ACCOUNT")
	require.Equal(f.t, calls+1, f.calls.Load(), "a refused credential must reach the origin")
	return got
}

func accountBody(session, variant string) string {
	return "ACCOUNT: data of " + session + "/" + variant
}

// refusal answers with status, naming directive on the response: "bare" for
// none, "VaryStar" for Vary: *, anything else as a Cache-Control.
func refusal(status int, directive string) func(fiber.Ctx) error {
	return func(c fiber.Ctx) error {
		switch directive {
		case "bare":
		case "VaryStar":
			c.Set(fiber.HeaderVary, "*")
		default:
			c.Set(fiber.HeaderCacheControl, directive)
		}
		return c.SendStatus(status)
	}
}

// refusingAfter refuses with a 401 once strip has removed the credential, as a handler
// that clears a rejected session would.
func refusingAfter(strip func(*fasthttp.RequestHeader)) func(fiber.Ctx) error {
	return func(c fiber.Ctx) error {
		strip(&c.Request().Header)
		return c.SendStatus(fiber.StatusUnauthorized)
	}
}

// A reload answered 401, 403 or 407 ends the entry of the credential it was stored under and
// leaves other credentials' entries, with or without a directive on the refusal. A directive
// ends the manifest too, and so the variants of the sessions that share it.
func Test_Cache_RejectedCredentialDropsEntry(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"keyCookies", "varyCookie", "varyApiKey", "authorization"} {
		for _, storage := range storageKinds {
			for _, reload := range reloadForms {
				for _, status := range refusalStatuses {
					for _, directive := range []string{"bare", "private", "no-store", "no-cache", "VaryStar"} {
						t.Run(fmt.Sprintf("%s/%s/%s/%d/%s", partition, storage, reload, status, directive), func(t *testing.T) {
							t.Parallel()

							f := newCredentialFixture(t, &credentialOptions{
								partition: partition,
								storage:   storage,
								refuse:    refusal(status, directive),
							})

							bodySize := uint(len(accountBody("a", "")))
							f.warm([]string{"a", "b"})
							f.requireHit("a", "")
							require.Equal(t, 2*bodySize, f.probe.counted())
							require.Equal(t, 2, f.probe.nodes())

							// A refusal that found no entry of its own purges nothing.
							for _, cacheControl := range []string{"", reload} {
								got := f.get("stranger", "", cacheControl)
								require.Equal(t, status, got.status)
								require.Equal(t, cacheUnreachable, got.cache)
							}
							f.requireHit("b", "")
							f.requireHit("a", "")
							require.Equal(t, 2*bodySize, f.probe.counted())
							require.Equal(t, 2, f.probe.nodes())

							// The app ends the session; the reload reaches the origin.
							f.ended.Store("a", true)
							got := f.get("a", "", reload)
							require.Equal(t, status, got.status)
							require.Equal(t, cacheUnreachable, got.cache)

							// The same credential must now meet the origin again, not the old body.
							got = f.requireRefused(status, "", "")
							require.Equal(t, cacheUnreachable, got.cache)

							// The purge gave back exactly the refused entry's accounting.
							require.Equal(t, bodySize, f.probe.counted())
							require.Equal(t, 1, f.probe.nodes())

							// Only the refused credential's entry went, unless the refusal said not to keep a
							// response: then the manifest the sessions share went too.
							if directive != "bare" && (partition == "varyCookie" || partition == "varyApiKey") {
								require.Equal(t, cacheMiss, f.get("b", "", "").cache)
								return
							}
							f.requireHit("b", "")
						})
					}
				}
			}
		}
	}
}

// A handler that refuses by returning fiber.ErrUnauthorized writes no status, yet the refusal
// still ends the entry; an error that says nothing about the credential does not.
func Test_Cache_RejectedCredentialReturnedAsError(t *testing.T) {
	t.Parallel()

	answers := []struct {
		err    error
		name   string
		status int
		drops  bool
	}{
		{name: "401", err: fiber.ErrUnauthorized, status: fiber.StatusUnauthorized, drops: true},
		{name: "403", err: fiber.ErrForbidden, status: fiber.StatusForbidden, drops: true},
		{name: "407", err: fiber.ErrProxyAuthRequired, status: fiber.StatusProxyAuthRequired, drops: true},
		{name: "wrapped 401", err: fmt.Errorf("session expired: %w", fiber.ErrUnauthorized), status: fiber.StatusUnauthorized, drops: true},
		{name: "503", err: fiber.ErrServiceUnavailable, status: fiber.StatusServiceUnavailable},
		{name: "429", err: fiber.ErrTooManyRequests, status: fiber.StatusTooManyRequests},
		{name: "plain error", err: errors.New("session store unreachable"), status: fiber.StatusInternalServerError},
	}

	for _, partition := range []string{"keyCookies", "varyCookie", "authorization"} {
		for _, storage := range storageKinds {
			for _, reload := range reloadForms {
				for _, answer := range answers {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", partition, storage, reload, answer.name), func(t *testing.T) {
						t.Parallel()

						f := newCredentialFixture(t, &credentialOptions{
							partition: partition,
							storage:   storage,
							refuse:    func(fiber.Ctx) error { return answer.err },
						})
						f.warm([]string{"a", "b"})

						f.ended.Store("a", true)
						require.Equal(t, answer.status, f.get("a", "", reload).status)

						if answer.drops {
							f.requireRefused(answer.status, "", "")
						} else {
							calls := f.calls.Load()
							f.requireHit("a", "")
							require.Equal(t, calls, f.calls.Load())
						}

						f.requireHit("b", "")
					})
				}
			}
		}
	}
}

// A refusal ends the entry it revalidated, and the credential's other variants too: through the
// manifest when it is the credential's own, through a record when it is shared. It does so only
// for a credential, or when it says not to keep a response, which also ends a shared manifest.
func Test_Cache_RejectedCredentialDropsItsVariants(t *testing.T) {
	t.Parallel()

	noStore := refusal(fiber.StatusUnauthorized, "no-store")
	private := refusal(fiber.StatusUnauthorized, "private")
	scenarios := []struct {
		refuse      func(fiber.Ctx) error // the refusal, a bare 401 when nil
		name        string
		partition   string
		anonymous   bool
		kept        bool // the refused entry stays: the refusal is no verdict on a credential
		siblingKept bool // the credential's other variant stays
		othersFlush bool // the other sessions' variants are out of reach until the manifest is stored again
		recorded    bool // the refusal is recorded, so the credential's variants stay out when it is
	}{
		{name: "KeyCookies", partition: "keyCookies"},
		{name: "Authorization", partition: "authorization"},
		// The shared manifest stays; the refusal is recorded and the session's other variant is revalidated.
		{name: "Vary Cookie", partition: "varyCookie"},
		{name: "Vary X-API-Key", partition: "varyApiKey"},
		{name: "API key header", partition: "apiKey"},
		{name: "header declared in KeyCredentialHeaders", partition: "credentialHeader"},
		// A custom key is opaque, so the declared header is taken to be in it.
		{name: "custom KeyGenerator, declared header", partition: "customKey"},
		// Nothing marks these a credential, so a bare refusal leaves the shared entries alone.
		{name: "tenant header, not a credential", partition: "tenant", kept: true, siblingKept: true},
		{name: "undeclared header, bare refusal", partition: "customHeader", kept: true, siblingKept: true},
		{name: "undeclared Vary, bare refusal", partition: "customVary", kept: true, siblingKept: true},
		{name: "no credential in the key", partition: "keyCookies", anonymous: true, kept: true, siblingKept: true},
		// A refusal that says not to keep a response ends the manifest too: the key's own, or a shared one.
		{name: "undeclared header, private refusal", partition: "customHeader", refuse: private},
		{name: "undeclared Vary, private refusal", partition: "customVary", refuse: private, othersFlush: true},
		{name: "no credential in the key, no-store refusal", partition: "keyCookies", anonymous: true, refuse: noStore},
		{name: "Vary Cookie, no-store refusal", partition: "varyCookie", refuse: noStore, othersFlush: true, recorded: true},
		{name: "Vary X-API-Key, private refusal", partition: "varyApiKey", refuse: private, othersFlush: true, recorded: true},
		// The key is decided before the handler runs, so clearing the credential cannot change it.
		{
			name: "KeyCookies, cookie cleared by the handler", partition: "keyCookies",
			refuse: refusingAfter(func(h *fasthttp.RequestHeader) { h.DelAllCookies() }),
		},
		{
			name: "Authorization, header cleared by the handler", partition: "authorization",
			refuse: refusingAfter(func(h *fasthttp.RequestHeader) { h.Del(fiber.HeaderAuthorization) }),
		},
	}

	for _, storage := range storageKinds {
		for _, scenario := range scenarios {
			t.Run(storage+"/"+scenario.name, func(t *testing.T) {
				t.Parallel()

				refused, other := "a", "b"
				var valid []string
				if scenario.anonymous {
					// No cookie is sent, so the key is shared by every client without one.
					refused, valid = "", []string{"", "b"}
				}
				f := newCredentialFixture(t, &credentialOptions{
					partition: scenario.partition,
					storage:   storage,
					vary:      "X-Variant",
					valid:     valid,
					refuse:    scenario.refuse,
				})
				f.warm([]string{refused, other}, "one", "two")

				f.ended.Store(refused, true)
				got := f.get(refused, "one", "no-cache")
				require.Equal(t, fiber.StatusUnauthorized, got.status)
				require.Equal(t, cacheUnreachable, got.cache)

				got = f.get(refused, "one", "")
				if scenario.kept {
					require.Equal(t, cacheHit, got.cache, "a refusal that is no verdict on a credential ended the shared entry")
				} else {
					require.Equal(t, fiber.StatusUnauthorized, got.status, "the refused variant was answered from the cache")
				}

				got = f.get(refused, "two", "")
				if scenario.siblingKept {
					require.Equal(t, cacheHit, got.cache)
				} else {
					require.Equal(t, fiber.StatusUnauthorized, got.status, "a variant of the refused credential was answered from the cache")
				}

				if scenario.othersFlush {
					got = f.get(other, "one", "")
					require.Equal(t, accountBody(other, "one"), got.body)
					require.Equal(t, cacheMiss, got.cache, "the manifest the sessions share went with the refusal")

					// That miss stored the manifest again, which brings back the entries hung on it.
					// The refused credential's stay out through its record, and its next refusal says
					// not to keep a response once more, so the others are served again from the origin.
					if scenario.recorded {
						f.requireRefused(fiber.StatusUnauthorized, "two", "")
						for _, variant := range []string{"one", "two"} {
							require.Equal(t, accountBody(other, variant), f.get(other, variant, "").body)
						}
						return
					}
				}
				for _, variant := range []string{"one", "two"} {
					f.requireHit(other, variant)
				}
			})
		}
	}
}

// The documented recipe: a CacheInvalidator reporting ended sessions cuts one off at once, in
// every variant, even for a request that accepts stale entries.
func Test_Cache_InvalidatorCutsOffEndedSession(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"keyCookies", "varyCookie"} {
		for _, storage := range storageKinds {
			for _, request := range []struct{ name, cacheControl string }{{"plain", ""}, {"max-stale", "max-stale"}} {
				t.Run(partition+"/"+storage+"/"+request.name, func(t *testing.T) {
					t.Parallel()

					f := newCredentialFixture(t, &credentialOptions{
						partition:       partition,
						storage:         storage,
						vary:            "X-Variant",
						invalidateEnded: true,
					})
					variants := []string{"one", "two"}
					f.warm([]string{"a", "b"}, variants...)
					for _, variant := range variants {
						f.requireHit("a", variant)
					}

					f.ended.Store("a", true)
					for _, variant := range variants {
						f.requireRefused(fiber.StatusUnauthorized, variant, request.cacheControl)
					}

					for _, variant := range variants {
						f.requireHit("b", variant)
					}
				})
			}
		}
	}
}

// isRefusalRecord tells a refusal record from the marker announcing them.
func isRefusalRecord(key string) bool {
	return key != refusalMarker && strings.Contains(key, "|refused")
}

// refusalStorage counts the reads and writes of refusal records, and the reads of the marker
// announcing them, can fail the record reads, and says how many records it holds.
type refusalStorage struct {
	*failingCacheStorage
	reads       atomic.Int32
	writes      atomic.Int32
	markerReads atomic.Int32
	fail        atomic.Bool
}

func newRefusalStorage() *refusalStorage {
	return &refusalStorage{failingCacheStorage: newFailingCacheStorage()}
}

func (s *refusalStorage) SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error {
	if isRefusalRecord(key) {
		s.writes.Add(1)
	}
	return s.failingCacheStorage.SetWithContext(ctx, key, val, exp)
}

// records is how many refusal records the storage holds.
func (s *refusalStorage) records() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for key := range s.data {
		if isRefusalRecord(key) {
			n++
		}
	}
	return n
}

func (s *refusalStorage) GetWithContext(ctx context.Context, key string) ([]byte, error) {
	if key == refusalMarker {
		s.markerReads.Add(1)
	}
	if isRefusalRecord(key) {
		s.reads.Add(1)
		if s.fail.Load() {
			return nil, errors.New("storage unavailable")
		}
	}
	return s.failingCacheStorage.GetWithContext(ctx, key)
}

// A refused session's other variants stay out whatever other sessions do: a miss of theirs stores the manifest again.
func Test_Cache_RefusedCredentialStaysOutWhileOthersMiss(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"varyCookie", "varyApiKey"} {
		for _, storage := range storageKinds {
			for _, directive := range []string{"bare"} {
				t.Run(partition+"/"+storage+"/"+directive, func(t *testing.T) {
					t.Parallel()

					f := newCredentialFixture(t, &credentialOptions{
						partition: partition,
						storage:   storage,
						vary:      "X-Variant",
						refuse:    refusal(fiber.StatusUnauthorized, directive),
					})
					f.warm([]string{"a", "b"}, "one", "two")

					f.ended.Store("a", true)
					require.Equal(t, fiber.StatusUnauthorized, f.get("a", "one", "no-cache").status)

					// Another session misses on a variant of its own, which stores the manifest again.
					require.Equal(t, cacheMiss, f.get("b", "three", "").cache)

					f.requireRefused(fiber.StatusUnauthorized, "two", "")

					for _, variant := range []string{"one", "two", "three"} {
						f.requireHit("b", variant)
					}
				})
			}
		}
	}
}

// A hit looks for a refusal record only once one is announced, and then only for an entry that
// a credential selected: the key holds it, or the Vary names it. An anonymous client has none.
func Test_Cache_RefusalRecordIsReadOnlyWhereOneCanApply(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		partition string
		vary      string
		reads     int32 // per hit, once a record is announced
		anonymous bool
	}{
		{name: "no Vary", partition: "tenant"},
		{name: "Vary: X-Variant", partition: "tenant", vary: "X-Variant"},
		{name: "Vary: Cookie", partition: "varyCookie", reads: 1},
		{name: "Vary: Cookie, X-Variant", partition: "varyCookie", vary: "X-Variant", reads: 1},
		{name: "Vary: X-API-Key", partition: "varyApiKey", reads: 1},
		{name: "Vary: Cookie, no cookie sent", partition: "varyCookie", anonymous: true},
		{name: "Vary: X-API-Key, no key sent", partition: "varyApiKey", anonymous: true},
		{name: "the key holds the cookie", partition: "keyCookies", reads: 1},
		{name: "the key holds the credential header", partition: "apiKey", reads: 1},
		{name: "the key holds Authorization", partition: "authorization", reads: 1},
	} {
		for _, announced := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/announced=%t", tc.name, announced), func(t *testing.T) {
				t.Parallel()

				session := "a"
				if tc.anonymous {
					session = ""
				}
				storage := newRefusalStorage()
				if announced {
					storage.data[refusalMarker] = []byte{1}
				}
				f := newCredentialFixture(t, &credentialOptions{
					partition: tc.partition,
					custom:    storage,
					vary:      tc.vary,
					valid:     []string{session},
				})
				require.Equal(t, cacheMiss, f.get(session, "", "").cache)
				require.Zero(t, storage.reads.Load(), "a miss has nothing to check")

				for range 3 {
					require.Equal(t, cacheHit, f.get(session, "", "").cache)
				}
				want := int32(0)
				if announced {
					want = 3 * tc.reads
				}
				require.Equal(t, want, storage.reads.Load())
				// The marker is read once a second, however many hits there are.
				require.LessOrEqual(t, storage.markerReads.Load(), int32(2))
			})
		}
	}
}

// A storage that cannot say whether the credential was refused revalidates rather than serves.
func Test_Cache_UnreadableRefusalRecordRevalidates(t *testing.T) {
	t.Parallel()

	storage := newRefusalStorage()
	storage.data[refusalMarker] = []byte{1}
	f := newCredentialFixture(t, &credentialOptions{
		partition: "varyCookie",
		custom:    storage,
		valid:     []string{"a"},
	})
	require.Equal(t, cacheMiss, f.get("a", "", "").cache)
	require.Equal(t, cacheHit, f.get("a", "", "").cache)

	storage.fail.Store(true)
	calls := f.calls.Load()
	got := f.get("a", "", "")
	require.Equal(t, cacheMiss, got.cache)
	require.Equal(t, calls+1, f.calls.Load(), "the entry must reach the origin")
}

// A client that sends no credential is turned away for reasons the cache cannot see, so its
// refusal leaves the entry every such client shares, unless the refusal says not to keep one. No
// record is made or read: there is no credential to record it under.
func Test_Cache_RefusedAnonymousClientLeavesTheSharedEntry(t *testing.T) {
	t.Parallel()

	// The partitions whose manifest the anonymous client shares with the others.
	shared := map[string]bool{"varyCookie": true, "varyApiKey": true, "customVary": true}

	for _, partition := range []string{"varyCookie", "varyApiKey", "tenant", "customHeader", "customVary"} {
		for _, storage := range storageKinds {
			for _, reload := range reloadForms {
				for _, status := range refusalStatuses {
					for _, directive := range []string{"bare", "no-store"} {
						t.Run(fmt.Sprintf("%s/%s/%s/%d/%s", partition, storage, reload, status, directive), func(t *testing.T) {
							t.Parallel()

							backing := newRefusalStorage()
							opts := &credentialOptions{partition: partition, valid: []string{"", "a"}, refuse: refusal(status, directive)}
							if storage == "external" {
								opts.custom = backing
							}
							f := newCredentialFixture(t, opts)
							f.warm([]string{"", "a"})
							f.requireHit("", "")

							// A refusal that found no entry of its own ends nothing.
							f.requireRefusedAs(status, "stranger", "", reload)
							f.requireHit("", "")

							// The app starts turning away clients that send no credential.
							f.ended.Store("", true)
							f.requireRefusedAs(status, "", "", reload)
							require.Zero(t, backing.writes.Load(), "an anonymous client has no credential to record a refusal of")
							require.Zero(t, backing.reads.Load(), "an anonymous client has no record to be checked against")

							if directive == "bare" {
								// Nothing says the entry is no longer fit to keep, so it still answers.
								f.requireHit("", "")
								f.requireHit("a", "")
								return
							}
							// The refusal said not to keep a response: the entry went, and the manifest
							// with it, which takes the sessions that share it out of reach.
							f.requireRefusedAs(status, "", "", "")
							if shared[partition] {
								require.Equal(t, cacheMiss, f.get("a", "", "").cache)
								return
							}
							f.requireHit("a", "")
						})
					}
				}
			}
		}
	}
}

// Once the origin accepts the credential again the refusal is forgotten: its entries are
// served without a trip to the origin and the record is gone.
func Test_Cache_RefusedCredentialRecoversWhenAccepted(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"varyCookie", "varyApiKey"} {
		t.Run(partition, func(t *testing.T) {
			t.Parallel()

			storage := newRefusalStorage()
			f := newCredentialFixture(t, &credentialOptions{
				partition: partition,
				custom:    storage,
				vary:      "X-Variant",
			})
			f.warm([]string{"a", "b"}, "one", "two")

			f.ended.Store("a", true)
			f.requireRefused(fiber.StatusUnauthorized, "one", "no-cache")
			require.Equal(t, 1, storage.records(), "the refusal is recorded")

			// Granted again: the other variant, still stored, goes to the origin once, which ends the record.
			f.ended.Delete("a")
			calls := f.calls.Load()
			require.Equal(t, cacheMiss, f.get("a", "two", "").cache)
			require.Equal(t, calls+1, f.calls.Load(), "the record must send the entry to the origin")
			require.Zero(t, storage.records(), "the record of a refusal that no longer stands goes")

			f.requireHit("a", "two")
			require.Equal(t, cacheMiss, f.get("a", "one", "").cache, "the refused entry was dropped")
			f.requireHit("a", "one")
			f.requireHit("b", "one")
		})
	}
}

// A refusal that lands after a concurrent request stored a replacement still puts the
// credential's entries out of reach: the replacement may be an answer it no longer gets.
func Test_Cache_RefusalOutlivesAConcurrentReplacement(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"keyCookies", "authorization", "varyCookie", "varyApiKey"} {
		for _, storage := range storageKinds {
			t.Run(partition+"/"+storage, func(t *testing.T) {
				t.Parallel()

				var armed atomic.Bool
				f := newCredentialFixture(t, &credentialOptions{
					partition: partition,
					storage:   storage,
					vary:      "X-Variant",
					beforeRefusal: func(f *credentialFixture) {
						if !armed.CompareAndSwap(true, false) {
							return
						}
						// Another request of the session, answered before it ended, stores its response meanwhile.
						f.ended.Delete("a")
						require.Equal(f.t, cacheMiss, f.get("a", "one", "max-age=0").cache)
						f.ended.Store("a", true)
					},
				})
				f.warm([]string{"a", "b"}, "one", "two")

				f.ended.Store("a", true)
				armed.Store(true)
				require.Equal(t, fiber.StatusUnauthorized, f.get("a", "one", "no-cache").status)
				require.False(t, armed.Load(), "the replacement was never stored")

				// Neither the replacement nor the other variant is served to the ended session.
				f.requireRefused(fiber.StatusUnauthorized, "one", "")
				f.requireRefused(fiber.StatusUnauthorized, "two", "")
				f.requireHit("b", "one")
			})
		}
	}
}

// Only a credential that has an entry gets a record, so records cannot outnumber the entries they guard.
func Test_Cache_RefusalsOfUnknownCredentialsWriteNoRecords(t *testing.T) {
	t.Parallel()

	storage := newRefusalStorage()
	f := newCredentialFixture(t, &credentialOptions{
		partition: "varyCookie",
		custom:    storage,
		valid:     []string{"a"},
	})
	require.Equal(t, cacheMiss, f.get("a", "", "").cache)

	for i := range 50 {
		got := f.get(fmt.Sprintf("stranger-%d", i), "", "no-cache")
		require.Equal(t, fiber.StatusUnauthorized, got.status)
	}
	require.Zero(t, storage.writes.Load(), "a credential with no entry got a record")
	require.Zero(t, storage.records())

	// The one credential that has an entry gets one, refused again and again.
	f.ended.Store("a", true)
	for range 3 {
		require.Equal(t, fiber.StatusUnauthorized, f.get("a", "", "no-cache").status)
	}
	require.Equal(t, int32(1), storage.writes.Load())
	require.Equal(t, 1, storage.records())
}

// A handler that fails for a request that found an entry leaves the cache as it was.
func Test_Cache_HandlerErrorKeepsTheEntry(t *testing.T) {
	t.Parallel()

	for _, storage := range storageKinds {
		t.Run(storage, func(t *testing.T) {
			t.Parallel()

			app := fiber.New()
			app.Use(New(Config{Storage: storageOf(storage)}))
			app.Get("/", func(c fiber.Ctx) error {
				if c.Get("X-Fail") == "1" {
					return fiber.ErrServiceUnavailable
				}
				return c.SendString("PUBLIC")
			})

			require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
			for _, reload := range []string{"no-cache", "max-age=0"} {
				got := getRoot(t, app, map[string]string{"X-Fail": "1", fiber.HeaderCacheControl: reload})
				require.Equal(t, fiber.StatusServiceUnavailable, got.status)
			}
			got := getRoot(t, app, nil)
			require.Equal(t, cacheHit, got.cache)
			require.Equal(t, "PUBLIC", got.body)
		})
	}
}

// An entry holding a credential's response is not served stale, though the storage keeps it past
// its lifetime, unless AllowStaleCredentialResponses says it may be.
func Test_Cache_CredentialKeyedEntryIgnoresMaxStale(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name      string
		partition string
		stale     bool // the expired entry is still served: nothing ties it to a credential
	}{
		{name: "KeyCookies", partition: "keyCookies"},
		{name: "Vary Cookie", partition: "varyCookie"},
		{name: "Vary X-API-Key", partition: "varyApiKey"},
		{name: "Authorization", partition: "authorization"},
		{name: "API key header named in KeyHeaders", partition: "apiKey"},
		{name: "header declared in KeyCredentialHeaders", partition: "credentialHeader"},
		{name: "tenant header, not a credential", partition: "tenant", stale: true},
	}

	for _, storage := range storageKinds {
		for _, maxStale := range []string{"max-stale", "max-stale=3600"} {
			for _, allowed := range []bool{false, true} {
				for _, scenario := range scenarios {
					t.Run(fmt.Sprintf("%s/%s/allowed=%t/%s", storage, maxStale, allowed, scenario.name), func(t *testing.T) {
						t.Parallel()

						clock := newTestClock(time.Unix(1_700_000_000, 0))
						f := newCredentialFixture(t, &credentialOptions{
							partition:  scenario.partition,
							storage:    storage,
							clock:      clock,
							expiration: time.Minute,
							allowStale: allowed,
						})
						f.warm([]string{"a", "b"})

						// Past the entry's lifetime, well inside what the storage keeps.
						clock.Add(2 * time.Minute)
						f.ended.Store("a", true)
						if scenario.stale || allowed {
							calls := f.calls.Load()
							got := f.get("a", "", maxStale)
							require.Equal(t, fiber.StatusOK, got.status)
							require.Equal(t, accountBody("a", ""), got.body)
							require.Equal(t, cacheHit, got.cache)
							require.Contains(t, got.header.Get(fiber.HeaderWarning), "110")
							require.Equal(t, calls, f.calls.Load())
							return
						}
						f.requireRefused(fiber.StatusUnauthorized, "", maxStale)
					})
				}
			}
		}
	}
}

// Allowing stale credential responses never revives an entry the app invalidated.
func Test_Cache_AllowStaleCredentialResponsesKeepsInvalidatedEntriesOut(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"keyCookies", "varyCookie", "authorization"} {
		for _, storage := range storageKinds {
			t.Run(partition+"/"+storage, func(t *testing.T) {
				t.Parallel()

				clock := newTestClock(time.Unix(1_700_000_000, 0))
				f := newCredentialFixture(t, &credentialOptions{
					partition:       partition,
					storage:         storage,
					clock:           clock,
					expiration:      time.Minute,
					allowStale:      true,
					invalidateEnded: true,
				})
				f.warm([]string{"a", "b"})
				clock.Add(2 * time.Minute)

				// The session that has not ended is served stale; the one that has is not.
				got := f.get("b", "", "max-stale")
				require.Equal(t, cacheHit, got.cache)
				f.ended.Store("a", true)
				f.requireRefused(fiber.StatusUnauthorized, "", "max-stale")
			})
		}
	}
}

// A refusal ends the entry it revalidated when it is a verdict on a credential, or says not to
// keep a response. A client turned away for its own reasons (an IP or geo rule) must not end the
// entry the others share: not one the key tells apart by nothing, and not one under a custom
// KeyGenerator, whose key is opaque, unless the client sends a credential the key may hold.
func Test_Cache_RefusalEndsTheSharedEntryOnlyForACredential(t *testing.T) {
	t.Parallel()

	custom := Config{KeyGenerator: pathKey}
	tests := []struct {
		blocked   map[string]string // what the client the app refuses sends besides X-Blocked
		name      string
		directive string // the Cache-Control the refusal carries, if any
		cfg       Config
		kept      bool
	}{
		{name: "default key", kept: true},
		{name: "default key, a cookie the key does not hold", blocked: map[string]string{"Cookie": "sid=1"}, kept: true},
		{name: "default key, a credential header the key does not hold", blocked: map[string]string{"X-API-Key": "k"}, kept: true},
		{name: "KeyHeaders naming a tenant", cfg: Config{KeyHeaders: []string{"X-Tenant"}}, kept: true},
		{name: "KeyCookies the request does not carry", cfg: Config{KeyCookies: []string{"session"}}, kept: true},
		{name: "custom KeyGenerator, client with an undeclared cookie", cfg: custom, blocked: map[string]string{"Cookie": "sid=1"}, kept: true},
		{name: "custom KeyGenerator, anonymous client", cfg: custom, kept: true},
		{
			name: "custom KeyGenerator, client with a header that is no credential",
			cfg:  custom, blocked: map[string]string{"X-Tenant": "acme"}, kept: true,
		},
		{
			name:    "custom KeyGenerator, client with a declared cookie",
			cfg:     Config{KeyGenerator: pathKey, KeyCredentialHeaders: []string{"Cookie"}},
			blocked: map[string]string{"Cookie": "sid=1"},
		},
		{
			name:    "custom KeyGenerator, client with a declared header",
			cfg:     Config{KeyGenerator: pathKey, KeyCredentialHeaders: []string{"X-Company-Token"}},
			blocked: map[string]string{"X-Company-Token": "t"},
		},
		{name: "custom KeyGenerator, client with a built-in credential header", cfg: custom, blocked: map[string]string{"X-API-Key": "k"}},
		// Whoever is refused, a refusal that says not to keep the entry ends it.
		{name: "default key, anonymous client, refusal says no-store", directive: "no-store"},
		{name: "custom KeyGenerator, anonymous client, refusal says no-store", cfg: custom, directive: "no-store"},
	}

	for _, storage := range storageKinds {
		for _, delivery := range []string{"status", "error"} {
			for _, reload := range reloadForms {
				for _, status := range refusalStatuses {
					for _, tc := range tests {
						// A refusal returned as an error is judged by its status alone.
						if tc.directive != "" && delivery == "error" {
							continue
						}
						t.Run(fmt.Sprintf("%s/%s/%s/%d/%s", storage, delivery, reload, status, tc.name), func(t *testing.T) {
							t.Parallel()

							cfg := tc.cfg
							cfg.Storage = storageOf(storage)
							app := fiber.New()
							app.Use(New(cfg))
							app.Get("/", func(c fiber.Ctx) error {
								if c.Get("X-Blocked") != "1" {
									return c.SendString("PUBLIC")
								}
								if tc.directive != "" {
									c.Set(fiber.HeaderCacheControl, tc.directive)
								}
								if delivery == "error" {
									return fiber.NewError(status)
								}
								return c.SendStatus(status)
							})

							require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
							require.Equal(t, cacheHit, getRoot(t, app, nil).cache)

							// A client the app refuses, whatever the key tells of it, reloads.
							headers := map[string]string{"X-Blocked": "1", fiber.HeaderCacheControl: reload}
							maps.Copy(headers, tc.blocked)
							require.Equal(t, status, getRoot(t, app, headers).status)

							want := cacheMiss
							if tc.kept {
								want = cacheHit
							}
							require.Equal(t, want, getRoot(t, app, nil).cache)
						})
					}
				}
			}
		}
	}
}

// The key tells a credential's variants apart by more than the Vary (the Accept header, by
// default), and a refusal of one ends the others: a record under the key without those dimensions
// reaches them.
func Test_Cache_RefusalReachesTheVariantsTheKeyTellsApart(t *testing.T) {
	t.Parallel()

	for _, partition := range []string{"keyCookies", "credentialHeader", "authorization", "varyCookie", "varyApiKey"} {
		for _, storage := range storageKinds {
			t.Run(partition+"/"+storage, func(t *testing.T) {
				t.Parallel()

				f := newCredentialFixture(t, &credentialOptions{
					partition:     partition,
					storage:       storage,
					variantHeader: fiber.HeaderAccept,
				})
				variants := []string{"text/html", "application/json"}
				f.warm([]string{"a", "b"}, variants...)

				f.ended.Store("a", true)
				f.requireRefused(fiber.StatusUnauthorized, variants[0], "no-cache")

				// A variant the key keeps apart is an entry of its own, and was served from the cache.
				f.requireRefused(fiber.StatusUnauthorized, variants[1], "")
				for _, variant := range variants {
					f.requireHit("b", variant)
				}
			})
		}
	}
}

// The origin accepting the credential again ends the record even when it does not store the
// answer, or the credential's entries would be revalidated until the record expired.
func Test_Cache_RefusalIsForgottenWhenTheAnswerIsNotStored(t *testing.T) {
	t.Parallel()

	storage := newRefusalStorage()
	f := newCredentialFixture(t, &credentialOptions{
		partition: "varyCookie",
		custom:    storage,
		vary:      "X-Variant",
	})
	f.warm([]string{"a", "b"}, "one", "two")

	f.ended.Store("a", true)
	f.requireRefused(fiber.StatusUnauthorized, "one", "no-cache")
	require.Equal(t, 1, storage.records())

	f.ended.Delete("a")
	f.noStore.Store(true)
	require.Equal(t, cacheUnreachable, f.get("a", "two", "").cache)
	require.Zero(t, storage.records(), "the record of a refusal that no longer stands is still there")

	f.noStore.Store(false)
	require.Equal(t, cacheMiss, f.get("a", "two", "").cache)
	f.requireHit("a", "two")
}

// An entry found expired is deleted unless a concurrent request replaced it meanwhile, which a
// slow CacheInvalidator makes likely.
func Test_Cache_ExpiredDeleteKeepsAConcurrentReplacement(t *testing.T) {
	t.Parallel()

	for _, storage := range storageKinds {
		t.Run(storage, func(t *testing.T) {
			t.Parallel()

			clock := newTestClock(time.Unix(1_700_000_000, 0))
			gate := make(chan struct{})
			entered := make(chan struct{}, 1)
			inHandler := make(chan struct{}, 1)
			release := make(chan struct{})

			app := fiber.New()
			app.Use(New(Config{
				Storage:    storageOf(storage),
				Expiration: time.Minute,
				clock:      clock.Now,
				CacheInvalidator: func(c fiber.Ctx) bool {
					if c.Get("X-Slow") == "1" {
						entered <- struct{}{}
						<-gate
					}
					return false
				},
			}))
			app.Get("/", func(c fiber.Ctx) error {
				if c.Get("X-Slow") == "1" {
					inHandler <- struct{}{}
					<-release
					return c.SendString("slow")
				}
				return c.SendString("fresh")
			})

			require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
			clock.Add(2 * time.Minute)

			// The slow request finds the expired entry and waits in the invalidator.
			type result struct {
				resp *http.Response
				err  error
			}
			done := make(chan result, 1)
			go func() {
				req := httptest.NewRequest(fiber.MethodGet, "/", http.NoBody)
				req.Header.Set("X-Slow", "1")
				resp, err := app.Test(req)
				done <- result{resp, err}
			}()
			<-entered

			// Another request replaces the entry it found expired, then the slow one resumes.
			require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
			close(gate)
			<-inHandler

			require.Equal(t, cacheHit, getRoot(t, app, nil).cache, "the delete of the expired entry took the replacement with it")
			close(release)
			res := <-done
			require.NoError(t, res.err)
			require.NoError(t, res.resp.Body.Close())
		})
	}
}

// Every freshness decision follows CacheInvalidator and is made as of the same instant: an
// entry that a slow call ages past the request's max-age is revalidated, not served.
func Test_Cache_InvalidatorRunsBeforeFreshnessIsJudged(t *testing.T) {
	t.Parallel()

	for _, storage := range storageKinds {
		t.Run(storage, func(t *testing.T) {
			t.Parallel()

			clock := newTestClock(time.Unix(1_700_000_000, 0))
			var calls atomic.Int32
			app := fiber.New()
			app.Use(New(Config{
				Storage:    storageOf(storage),
				Expiration: time.Hour,
				clock:      clock.Now,
				CacheInvalidator: func(c fiber.Ctx) bool {
					if c.Get("X-Slow") == "1" {
						clock.Add(40 * time.Second)
					}
					return false
				},
			}))
			app.Get("/", func(c fiber.Ctx) error {
				return c.SendString("response-" + strconv.Itoa(int(calls.Add(1))))
			})

			require.Equal(t, "response-1", getRoot(t, app, nil).body)
			clock.Add(30 * time.Second)

			got := getRoot(t, app, map[string]string{"X-Slow": "1", fiber.HeaderCacheControl: "max-age=60"})
			require.Equal(t, "response-2", got.body, "an entry the call aged past max-age was served")
		})
	}
}

// An in-memory cache keeps no more refusal records than its limit. Dropping one that is still live
// must not let the credential it guarded be served: the cache fails closed until it would have
// lapsed, and every credentialed hit is revalidated meanwhile.
func Test_Cache_RefusalRecordOverflowFailsClosed(t *testing.T) {
	t.Parallel()

	sessions := []string{"s1", "s2", "s3", "s4"}
	f := newCredentialFixture(t, &credentialOptions{
		partition: "varyCookie",
		storage:   "memory",
		vary:      "X-Variant",
		valid:     append([]string{"b"}, sessions...),
		recordCap: 2,
	})
	f.warm(append([]string{"b"}, sessions...), "one", "two")

	// Four sessions are refused where two records fit: the first two records are dropped live.
	for _, session := range sessions {
		f.ended.Store(session, true)
		f.requireRefusedAs(fiber.StatusUnauthorized, session, "one", "no-cache")
	}

	// None of the refused sessions is served its other variant, the ones whose record went included.
	for _, session := range sessions {
		f.requireRefusedAs(fiber.StatusUnauthorized, session, "two", "")
	}

	// The others are answered rightly, from the origin while the cache fails closed.
	for _, variant := range []string{"one", "two"} {
		require.Equal(t, accountBody("b", variant), f.get("b", variant, "").body)
	}
}
