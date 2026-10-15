package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/utils/v2"
	"github.com/stretchr/testify/require"
)

func Test_carriesCredential(t *testing.T) {
	t.Parallel()

	cfg := configDefault(Config{KeyCredentialHeaders: []string{"X-Company-Token"}})
	for name, want := range map[string]bool{
		"Authorization":       true,
		"authorization":       true,
		"COOKIE":              true,
		"Proxy-Authorization": true,
		"X-API-Key":           true,
		"x-auth-token":        true,
		"X-Access-Token":      true,
		"X-Company-Token":     true,
		"x-company-token":     true,
		"X-Tenant":            false,
		"Accept-Language":     false,
		"Set-Cookie":          false,
		"X-Authorization":     false,
		"":                    false,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, want, cfg.carriesCredential(name))
		})
	}
}

// pathKey is the smallest custom KeyGenerator: the key is the path.
func pathKey(c fiber.Ctx) string { return c.Path() }

// requestWith returns the context of a request that carries the headers.
func requestWith(headers map[string]string) fiber.Ctx {
	c, _ := buildKeygenCtx(&keygenCase{uri: "/", headers: headers})
	return c
}

func Test_scopeOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		headers          map[string]string
		name             string
		vary             []string
		cfg              Config
		hasAuthorization bool
		wantEntry        bool
		wantKeyed        bool
	}{
		// The default key is built from the request, so a refusal reaches the entry found only
		// when that is the credential's own: the key holds it, or the Vary names it.
		{name: "nothing in the key"},
		{name: "Authorization", hasAuthorization: true, wantEntry: true, wantKeyed: true},
		{
			name: "KeyCookies cookie present", cfg: Config{KeyCookies: []string{"session"}},
			headers: map[string]string{"Cookie": "session=abc"}, wantEntry: true, wantKeyed: true,
		},
		{name: "KeyCookies cookie absent", cfg: Config{KeyCookies: []string{"session"}}},
		{
			name: "recognized header in KeyHeaders present", cfg: Config{KeyHeaders: []string{"X-API-Key"}},
			headers: map[string]string{"X-API-Key": "k"}, wantEntry: true, wantKeyed: true,
		},
		{name: "recognized header in KeyHeaders absent", cfg: Config{KeyHeaders: []string{"X-API-Key"}}},
		{
			name: "header in KeyHeaders that is not a credential", cfg: Config{KeyHeaders: []string{"X-Tenant"}},
			headers: map[string]string{"X-Tenant": "acme"},
		},
		{
			name: "declared header present", cfg: Config{KeyCredentialHeaders: []string{"X-Company-Token"}},
			headers: map[string]string{"X-Company-Token": "t"}, wantEntry: true, wantKeyed: true,
		},
		// The entry is shared by clients the credential does not tell apart.
		{name: "a cookie the key does not hold", headers: map[string]string{"Cookie": "a=b"}},
		{name: "a credential header the key does not hold", headers: map[string]string{"X-API-Key": "k"}},
		{
			name: "Vary names a credential the request sends", vary: []string{"cookie"},
			headers: map[string]string{"Cookie": "a=b"}, wantEntry: true,
		},
		{name: "Vary names a credential the request does not send", vary: []string{"cookie"}},
		{name: "Vary names a header that is not a credential", vary: []string{"x-tenant"}, headers: map[string]string{"X-Tenant": "acme"}},
		// A custom key is opaque: the refusal needs a credential the key may hold (Authorization is in every key).
		{
			name: "custom KeyGenerator, request with an undeclared cookie", cfg: Config{KeyGenerator: pathKey},
			headers: map[string]string{"Cookie": "sid=1"},
		},
		{
			name: "custom KeyGenerator, request with a declared cookie",
			cfg:  Config{KeyGenerator: pathKey, KeyCredentialHeaders: []string{"Cookie"}}, headers: map[string]string{"Cookie": "sid=1"}, wantEntry: true,
		},
		{
			name: "custom KeyGenerator, request with a built-in credential header", cfg: Config{KeyGenerator: pathKey},
			headers: map[string]string{"X-API-Key": "k"}, wantEntry: true,
		},
		{
			name:    "custom KeyGenerator, request with a declared header",
			cfg:     Config{KeyGenerator: pathKey, KeyCredentialHeaders: []string{"X-Company-Token"}},
			headers: map[string]string{"X-Company-Token": "t"}, wantEntry: true,
		},
		{name: "custom KeyGenerator, Authorization", cfg: Config{KeyGenerator: pathKey}, hasAuthorization: true, wantEntry: true, wantKeyed: true},
		{
			name: "custom KeyGenerator, Vary names the cookie the request sends", cfg: Config{KeyGenerator: pathKey},
			vary: []string{"cookie"}, headers: map[string]string{"Cookie": "sid=1"}, wantEntry: true,
		},
		// Nothing the key could hold: a client turned away for its own reasons must not end the shared entry.
		{name: "custom KeyGenerator, anonymous request", cfg: Config{KeyGenerator: pathKey}},
		{
			name: "custom KeyGenerator, request with a header that is not a credential", cfg: Config{KeyGenerator: pathKey},
			headers: map[string]string{"X-Tenant": "acme"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := configDefault(tc.cfg)
			scope := cfg.scopeOf(requestWith(tc.headers), tc.vary, tc.hasAuthorization)
			require.Equal(t, tc.wantEntry, scope.entry, "entry")
			require.Equal(t, tc.wantKeyed, scope.keyed, "keyed")
		})
	}
}

func Test_keyLog(t *testing.T) {
	t.Parallel()

	t.Run("forgets the oldest past its limit, with the second it lapses", func(t *testing.T) {
		t.Parallel()

		l := &keyLog{limit: 2}
		require.Empty(t, l.add("a", 10).key)
		require.Empty(t, l.add("b", 20).key)
		require.Equal(t, loggedKey{key: "a", until: 10}, l.add("c", 30))
		require.Equal(t, loggedKey{key: "b", until: 20}, l.add("d", 40))
	})

	t.Run("a key seen again is the newest, and lapses at the later second", func(t *testing.T) {
		t.Parallel()

		l := &keyLog{limit: 2}
		l.add("a", 10)
		l.add("b", 20)
		require.Empty(t, l.add("a", 50).key)
		require.Empty(t, l.add("a", 5).key)
		require.Equal(t, loggedKey{key: "b", until: 20}, l.add("c", 30))
		require.Equal(t, loggedKey{key: "a", until: 50}, l.add("d", 40))
	})

	t.Run("a removed key leaves room", func(t *testing.T) {
		t.Parallel()

		l := &keyLog{limit: 2}
		l.add("a", 10)
		l.add("b", 20)
		l.remove("a")
		l.remove("never seen")
		require.Empty(t, l.add("c", 30).key)
		require.Equal(t, "b", l.add("d", 40).key)
	})

	t.Run("no limit forgets nothing, so keeps nothing", func(t *testing.T) {
		t.Parallel()

		l := &keyLog{}
		for i := range 100 {
			require.Empty(t, l.add(strconv.Itoa(i), 10).key)
		}
		require.Empty(t, l.items)
	})
}

func Test_refusalLimit(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		cfg  Config
		want int
	}{
		{name: "sized by MaxBytes", cfg: Config{MaxBytes: 1 << 20}, want: 4096},
		{name: "never fewer than the minimum", cfg: Config{MaxBytes: 1}, want: minRefusalRecords},
		{name: "a default when MaxBytes sets no limit", cfg: Config{}, want: unlimitedRefusalRecords},
		{name: "overridden", cfg: Config{MaxBytes: 1 << 20, refusalRecordLimit: 7}, want: 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, tc.cfg.refusalLimit())
		})
	}
}

// A record can exist in the in-memory store only until the last written has expired, and in a
// Storage when another instance announced one.
func Test_refusalRecords_mayHold(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("in memory, from the first record until the last has expired", func(t *testing.T) {
		t.Parallel()

		cfg := configDefault(Config{})
		records := newRefusalRecords(&cfg, newManager(nil, true))
		require.False(t, records.mayHold(ctx))

		records.record(ctx, "base|refused|vary|digest", 0)
		require.True(t, records.mayHold(ctx))

		// The store drops its records at its own clock, which is the one read here.
		records.until.Store(uint64(utils.Timestamp()))
		require.False(t, records.mayHold(ctx))
	})

	t.Run("a record is kept for Expiration, or as long as the refused entry had left", func(t *testing.T) {
		t.Parallel()

		now := time.Unix(1_700_000_000, 0)
		cfg := configDefault(Config{Expiration: time.Minute, clock: func() time.Time { return now }})
		kept := func(entryExp uint64) uint64 {
			records := newRefusalRecords(&cfg, newManager(nil, true))
			before := uint64(utils.Timestamp())
			records.record(ctx, "base|refused|vary|digest", entryExp)
			return records.until.Load() - before
		}
		// Whole seconds, plus the two the gate adds to cover the store's rounding and a tick.
		within := func(got, seconds uint64) {
			t.Helper()
			require.GreaterOrEqual(t, got, seconds+2)
			require.LessOrEqual(t, got, seconds+6)
		}

		within(kept(0), 60)
		within(kept(uint64(now.Unix())+10), 60)
		within(kept(uint64(now.Unix())+3600), 3600)
	})

	t.Run("in a Storage, when a marker says so", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		cfg := configDefault(Config{Storage: storage})
		records := newRefusalRecords(&cfg, newManager(storage, true))
		require.False(t, records.mayHold(ctx))

		// Another instance announces a record. It is noticed once the second's verdict is stale.
		storage.data[refusalMarker] = []byte{1}
		records.seen.Store(0)
		require.True(t, records.mayHold(ctx))
	})

	t.Run("in a Storage, the marker is read once a second", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		cfg := configDefault(Config{Storage: storage})
		records := newRefusalRecords(&cfg, newManager(storage, true))

		// With the second's verdict stored, the marker is not asked for: it is not there.
		for {
			now := uint64(utils.Timestamp())
			records.seen.Store(now)
			records.open.Store(true)
			got := records.mayHold(ctx)
			if uint64(utils.Timestamp()) == now {
				require.True(t, got)
				break
			}
		}
	})

	t.Run("in a Storage that cannot answer, a record is taken to exist", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		storage.errs["get|"+refusalMarker] = errors.New("storage unavailable")
		cfg := configDefault(Config{Storage: storage})
		require.True(t, newRefusalRecords(&cfg, newManager(storage, true)).mayHold(ctx))
	})

	t.Run("a record written to a Storage is announced for the other instances", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		cfg := configDefault(Config{Storage: storage})
		records := newRefusalRecords(&cfg, newManager(storage, true))
		records.record(ctx, "base|refused|vary|digest", 0)
		require.Contains(t, storage.data, "base|refused|vary|digest")
		require.Contains(t, storage.data, refusalMarker)
		require.True(t, records.mayHold(ctx))
	})
}

// An in-memory store keeps no more records than its limit, so refusing many credentials cannot grow
// it unbounded; an external Storage expires its records itself, and forgetting a live one would lift
// its protection.
func Test_refusalRecords_bound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	keys := []string{"k1", "k2", "k3", "k4"}

	t.Run("an in-memory store forgets the oldest", func(t *testing.T) {
		t.Parallel()

		cfg := configDefault(Config{refusalRecordLimit: 2})
		records := newRefusalRecords(&cfg, newManager(nil, true))
		for _, key := range keys {
			records.record(ctx, key, 0)
		}
		held := func(key string) bool {
			_, err := records.m.getRaw(ctx, key)
			return err == nil
		}
		require.False(t, held("k1"))
		require.False(t, held("k2"))
		require.True(t, held("k3"))
		require.True(t, held("k4"))
	})

	t.Run("a record dropped while live fails the cache closed until it would have lapsed", func(t *testing.T) {
		t.Parallel()

		cfg := configDefault(Config{refusalRecordLimit: 2})
		records := newRefusalRecords(&cfg, newManager(nil, true))
		require.False(t, records.refused(ctx, "unknown"))
		for _, key := range keys {
			records.record(ctx, key, 0)
		}

		// k1 and k2 are gone from the store, so a key it never held is refused all the same.
		require.True(t, records.refused(ctx, "unknown"))
		require.True(t, records.mayHold(ctx))

		// Once the dropped records would have lapsed, it is an ordinary miss again.
		records.saturated.Store(uint64(utils.Timestamp()))
		require.False(t, records.refused(ctx, "unknown"))
	})

	t.Run("a record dropped later that lapses sooner does not shorten it", func(t *testing.T) {
		t.Parallel()

		cfg := configDefault(Config{refusalRecordLimit: 2})
		records := newRefusalRecords(&cfg, newManager(nil, true))
		hour := uint64(time.Now().Unix()) + 3600
		records.record(ctx, keys[0], hour)
		for _, key := range keys[1:] {
			records.record(ctx, key, 0)
		}
		require.GreaterOrEqual(t, records.saturated.Load(), hour)
	})

	t.Run("a record dropped after it lapsed costs nothing", func(t *testing.T) {
		t.Parallel()

		cfg := configDefault(Config{refusalRecordLimit: 1})
		records := newRefusalRecords(&cfg, newManager(nil, true))
		records.keys.add("old", uint64(utils.Timestamp())-10)
		records.record(ctx, "new", 0)
		require.Zero(t, records.saturated.Load())
		require.False(t, records.refused(ctx, "unknown"))
		require.True(t, records.refused(ctx, "new"))
	})

	t.Run("an external Storage keeps every record", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		cfg := configDefault(Config{Storage: storage, refusalRecordLimit: 2})
		records := newRefusalRecords(&cfg, newManager(storage, true))
		for _, key := range keys {
			records.record(ctx, key, 0)
		}
		for _, key := range keys {
			require.True(t, records.refused(ctx, key), key)
		}
	})
}

func Test_refusesCredential(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status int
		want   bool
	}{
		{status: fiber.StatusUnauthorized, want: true},
		{status: fiber.StatusForbidden, want: true},
		{status: fiber.StatusProxyAuthRequired, want: true},
		{status: fiber.StatusOK},
		{status: fiber.StatusFound},
		{status: fiber.StatusNotFound},
		{status: fiber.StatusTooManyRequests},
		{status: fiber.StatusServiceUnavailable},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, refusesCredential(tc.status))
		})
	}
}

func Test_errorRefusesCredential(t *testing.T) {
	t.Parallel()

	// A nil *fiber.Error held in an error matches errors.As, and must not be read.
	var typedNil *fiber.Error

	for _, tc := range []struct {
		err  error
		name string
		want bool
	}{
		{name: "nil"},
		{name: "401", err: fiber.ErrUnauthorized, want: true},
		{name: "403", err: fiber.ErrForbidden, want: true},
		{name: "407", err: fiber.ErrProxyAuthRequired, want: true},
		{name: "custom message", err: fiber.NewError(fiber.StatusForbidden, "tenant suspended"), want: true},
		{name: "wrapped", err: fmt.Errorf("session: %w", fiber.ErrUnauthorized), want: true},
		{name: "joined", err: errors.Join(errors.New("audit failed"), fiber.ErrForbidden), want: true},
		{name: "503", err: fiber.ErrServiceUnavailable},
		{name: "404", err: fiber.ErrNotFound},
		{name: "not a fiber error", err: errors.New("unauthorized")},
		{name: "typed nil", err: typedNil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, errorRefusesCredential(tc.err))
		})
	}
}

func Test_varyListsCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		vary     string
		declared []string
		want     bool
	}{
		{vary: "", want: false},
		{vary: "Accept", want: false},
		{vary: "Accept-Encoding, Accept-Language", want: false},
		{vary: "*", want: false},
		{vary: "Cookie", want: true},
		{vary: "cookie", want: true},
		{vary: "COOKIE", want: true},
		{vary: " Cookie ", want: true},
		{vary: "Accept-Encoding, Cookie", want: true},
		{vary: "Accept-Encoding,Cookie", want: true},
		{vary: "Authorization", want: true},
		{vary: "authorization", want: true},
		// The other headers that carry nothing but a credential.
		{vary: "Proxy-Authorization", want: true},
		{vary: "X-API-Key", want: true},
		{vary: "Accept, x-auth-token", want: true},
		{vary: "X-Access-Token", want: true},
		// Names that merely contain one of them are other fields.
		{vary: "X-Cookie", want: false},
		{vary: "Cookie2", want: false},
		{vary: "Set-Cookie", want: false},
		{vary: "X-Authorization", want: false},
		// A header is a credential only when it is declared.
		{vary: "X-Company-Token", want: false},
		{vary: "X-Company-Token", declared: []string{"x-company-token"}, want: true},
		{vary: "Accept, X-COMPANY-TOKEN", declared: []string{"x-company-token"}, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.vary, func(t *testing.T) {
			t.Parallel()
			cfg := Config{KeyCredentialHeaders: tc.declared}
			require.Equal(t, tc.want, cfg.varyListsCredential([]byte(tc.vary)), "Vary: %q", tc.vary)
		})
	}
}

func Test_refusalRecords_key(t *testing.T) {
	t.Parallel()

	records := func(cfg Config) *refusalRecords {
		cfg = configDefault(cfg)
		return newRefusalRecords(&cfg, newManager(nil, true))
	}
	session := map[string]string{"Cookie": "session=abc"}

	t.Run("there is nothing to record unless the credential is the entry's own", func(t *testing.T) {
		t.Parallel()

		r := records(Config{KeyCredentialHeaders: []string{"X-Company-Token"}})
		key := func(vary []string, headers map[string]string) string {
			return r.key(requestWith(headers), "base", vary, false)
		}
		require.Empty(t, key(nil, session), "no Vary, and the key holds no cookie")
		require.Empty(t, key([]string{"x-tenant"}, session), "a Vary on no credential")
		require.Empty(t, key([]string{"cookie"}, nil), "no credential sent")
		require.Empty(t, key([]string{"x-api-key"}, session), "another credential sent")
		require.NotEmpty(t, key([]string{"cookie"}, session))

		// The declared header is in the key, so that is the credential recorded.
		held := key([]string{"cookie"}, map[string]string{"X-Company-Token": "t"})
		require.Contains(t, held, "x-company-token:1sha256:")
		require.NotContains(t, held, "|vary|", "the Vary selects by a cookie the request does not send")
	})

	t.Run("a Vary on a credential is recorded under the credential and not the variant", func(t *testing.T) {
		t.Parallel()

		r := records(Config{})
		key := func(vary []string, headers map[string]string) string {
			return r.key(requestWith(headers), "base", vary, false)
		}
		got := key([]string{"cookie", "x-variant"}, session)
		require.Equal(t, got, key([]string{"cookie"}, session), "the other Vary names are not part of the record")
		require.Equal(t, got, key([]string{"cookie", "x-variant"}, map[string]string{"Cookie": "session=abc", "X-Variant": "two"}))
		require.NotEqual(t, got, key([]string{"cookie"}, map[string]string{"Cookie": "session=other"}))
		require.Equal(t, got, r.key(requestWith(session), "other base", []string{"cookie"}, false), "the key is built from the request")
		require.True(t, strings.HasPrefix(got, cacheKeyVersion+"|GET|"), "%q", got)
		require.Contains(t, got, "|refused|vary|")
	})

	t.Run("a credential the key holds is recorded without the other dimensions of the key", func(t *testing.T) {
		t.Parallel()

		withAccept := func(cookie, accept string) map[string]string {
			return map[string]string{"Cookie": "session=" + cookie, "Accept": accept}
		}
		for name, cfg := range map[string]Config{
			"KeyCookies":     {KeyCookies: []string{"session"}},
			"KeyHeaders":     {KeyHeaders: []string{"Accept", "X-API-Key"}},
			"KeyCredentialH": {KeyHeaders: []string{"Accept"}, KeyCredentialHeaders: []string{"X-Company-Token"}},
		} {
			r := records(cfg)
			credential := func(value, accept string) map[string]string {
				switch name {
				case "KeyCookies":
					return withAccept(value, accept)
				case "KeyHeaders":
					return map[string]string{"X-API-Key": value, "Accept": accept}
				default:
					return map[string]string{"X-Company-Token": value, "Accept": accept}
				}
			}
			key := func(value, accept string) string {
				return r.key(requestWith(credential(value, accept)), "base", nil, false)
			}

			got := key("abc", "text/html")
			require.NotEmpty(t, got, name)
			require.Equal(t, got, key("abc", "application/json"), "%s: a variant of another Accept", name)
			require.NotEqual(t, got, key("other", "text/html"), "%s: another credential", name)
			require.NotContains(t, got, "abc", name)
		}
		require.Empty(t, records(Config{KeyCookies: []string{"session"}}).key(requestWith(nil), "base", nil, false), "no cookie sent")
	})

	t.Run("Authorization is recorded under its digest", func(t *testing.T) {
		t.Parallel()

		r := records(Config{})
		key := func(auth string) string {
			return r.key(requestWith(map[string]string{"Authorization": auth, "Accept": "text/html"}), "base", nil, true)
		}
		got := key("Bearer one")
		require.NotEmpty(t, got)
		require.Contains(t, got, "|auth="+authDigest("Bearer one"))
		require.NotEqual(t, got, key("Bearer two"))
	})

	t.Run("a declared header is a credential held by a custom key, or not", func(t *testing.T) {
		t.Parallel()

		token := map[string]string{"X-Company-Token": "t"}
		record := func(cfg Config, vary []string, headers map[string]string) string {
			return records(cfg).key(requestWith(headers), "base", vary, false)
		}
		varyToken := []string{"x-company-token"}
		declared := Config{KeyCredentialHeaders: []string{"X-Company-Token"}}
		custom := Config{KeyCredentialHeaders: []string{"X-Company-Token"}, KeyGenerator: pathKey}

		// The default key is built from it, so the record is under the credential, not the base.
		got := record(declared, varyToken, token)
		require.NotEmpty(t, got)
		require.NotContains(t, got, "base")

		// A custom key ignores it, so the manifest is shared and the refusal gets a record under
		// the key it built, whatever the responses vary on.
		got = record(custom, varyToken, token)
		require.True(t, strings.HasPrefix(got, "base|refused|vary|"), "%q", got)
		require.NotEqual(t, got, record(custom, varyToken, map[string]string{"X-Company-Token": "u"}))
		require.Empty(t, record(custom, varyToken, nil))
		require.NotEmpty(t, record(custom, nil, token))
		require.Empty(t, records(custom).key(requestWith(token), "base", varyToken, true), "Authorization is in the key")
	})
}
