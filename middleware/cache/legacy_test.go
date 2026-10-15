package cache

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/utils/v2"
	"github.com/stretchr/testify/require"
)

// legacyCredential is a way for a key to hold a credential: the config that puts it there,
// how a request sends it, and how the current key version and the previous one wrote it.
type legacyCredential struct {
	send    func(credential string) map[string]string
	hashed  func(credential string) string
	spelled func(credential string) string
	name    string
	cfg     Config
}

// config returns the config of the credential for an external Storage.
func (lc *legacyCredential) config(storage fiber.Storage) Config {
	cfg := lc.cfg
	cfg.Storage = storage
	return cfg
}

func legacyCredentials() []legacyCredential {
	return []legacyCredential{
		{
			name:    "credential header",
			cfg:     Config{KeyHeaders: []string{"X-API-Key"}},
			send:    func(credential string) map[string]string { return map[string]string{"X-API-Key": credential} },
			hashed:  func(credential string) string { return "x-api-key:1sha256:" + authDigest(credential) },
			spelled: func(credential string) string { return "x-api-key:1|" + credential },
		},
		{
			name:    "KeyCookies cookie",
			cfg:     Config{KeyCookies: []string{"session"}},
			send:    func(credential string) map[string]string { return map[string]string{"Cookie": "session=" + credential} },
			hashed:  func(credential string) string { return "session:sha256:" + authDigest(credential) },
			spelled: func(credential string) string { return "session:" + credential },
		},
	}
}

// What the previous key version stored for a request, with the credential spelled out in its
// keys, is deleted when that request misses. Other credentials' entries stay.
func Test_legacyPurge_RemovesWhatThePreviousVersionStoredForTheRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range legacyCredentials() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const (
				token = "tok_0123456789abcdefghijklmnopqrstuvwxyz"
				other = "tok_other_other_other_other_other_other"
			)
			storage := newFailingCacheStorage()
			app := fiber.New()
			app.Use(New(tc.config(storage)))
			app.Get("/", func(c fiber.Ctx) error {
				c.Set(fiber.HeaderVary, "Accept-Language")
				return c.SendString("body")
			})
			withToken := tc.send(token)
			keys := func() []string {
				storage.mu.RLock()
				defer storage.mu.RUnlock()
				return slices.Collect(maps.Keys(storage.data))
			}

			// The current version keys the request without spelling the credential out.
			require.Equal(t, cacheMiss, getRoot(t, app, withToken).cache)
			var manifest, variant string
			for _, key := range keys() {
				require.NotContains(t, key, token)
				switch {
				case strings.HasSuffix(key, "|vary"):
					manifest = key
				case strings.Contains(key, "|vary|") && !strings.HasSuffix(key, "_body"):
					variant = key
				}
			}
			require.NotEmpty(t, manifest)
			require.NotEmpty(t, variant)
			base := strings.TrimSuffix(manifest, "|vary")
			require.Contains(t, base, tc.hashed(token))

			// What the previous version stored: the same keys under its version with the credential in
			// the clear, and another credential's beside them.
			legacy := func(credential string) []string {
				legacyBase := legacyKeyVersion + "|" + strings.TrimPrefix(strings.Replace(base, tc.hashed(token), tc.spelled(credential), 1), cacheKeyVersion+"|")
				legacyVariant := legacyBase + strings.TrimPrefix(variant, base)
				return []string{legacyBase, legacyBase + "_body", legacyBase + "|vary", legacyVariant, legacyVariant + "_body"}
			}
			plant := func(credential string) {
				storage.mu.Lock()
				defer storage.mu.Unlock()
				for _, key := range legacy(credential) {
					require.Contains(t, key, credential)
					storage.data[key] = []byte("accept-language")
				}
			}
			present := func(credential string) int {
				storage.mu.RLock()
				defer storage.mu.RUnlock()
				n := 0
				for _, key := range legacy(credential) {
					if _, ok := storage.data[key]; ok {
						n++
					}
				}
				return n
			}
			forgetCurrent := func() {
				storage.mu.Lock()
				defer storage.mu.Unlock()
				maps.DeleteFunc(storage.data, func(key string, _ []byte) bool {
					return strings.HasPrefix(key, cacheKeyVersion+"|")
				})
			}
			plant(token)
			plant(other)
			forgetCurrent()

			// A request without the credential is not the one those entries were stored for.
			require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
			require.Equal(t, 5, present(token))
			forgetCurrent()

			// The one that sends it ends them, and stores its answer under the current version.
			require.Equal(t, cacheMiss, getRoot(t, app, withToken).cache)
			require.Zero(t, present(token), "the credential is still spelled out in a key")
			require.Equal(t, 5, present(other), "another credential's entries went with it")
			for _, key := range keys() {
				if strings.HasPrefix(key, cacheKeyVersion+"|") {
					require.NotContains(t, key, token)
				}
			}
			require.Equal(t, cacheHit, getRoot(t, app, withToken).cache)
		})
	}
}

// The purge adds bounded work, and only where the previous version can have left something.
func Test_legacyPurge_IsBoundedAndOnlyWhereItCanMatter(t *testing.T) {
	t.Parallel()

	t.Run("not for memory, a custom key or nothing the key hashes", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		for name, cfg := range map[string]Config{
			"memory":                   {KeyHeaders: []string{"X-API-Key"}},
			"memory with a cookie":     {KeyCookies: []string{"session"}},
			"custom key":               {Storage: storage, KeyHeaders: []string{"X-API-Key"}, KeyGenerator: pathKey},
			"custom key with a cookie": {Storage: storage, KeyCookies: []string{"session"}, KeyGenerator: pathKey},
			"no credential or cookie":  {Storage: storage},
			// The previous version had no such option, so it kept nothing of the kind in its keys.
			"only a declared header": {Storage: storage, KeyCredentialHeaders: []string{"X-Company-Token"}},
		} {
			cfg = configDefault(cfg)
			require.Nil(t, newLegacyPurge(&cfg, nil), name)
		}
	})

	t.Run("for a credential header or a cookie of the key", func(t *testing.T) {
		t.Parallel()

		for _, tc := range legacyCredentials() {
			cfg := configDefault(tc.config(newFailingCacheStorage()))
			require.NotNil(t, newLegacyPurge(&cfg, nil), tc.name)
		}
	})

	t.Run("keys the headers as the previous version did", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		cfg := configDefault(Config{
			Storage:              storage,
			KeyHeaders:           []string{"X-API-Key"},
			KeyCredentialHeaders: []string{"X-Company-Token"},
		})
		purge := newLegacyPurge(&cfg, newManager(storage, true))
		require.NotNil(t, purge)

		// The declared header was added by the upgrade: the previous version left it out of its keys.
		withToken := requestWith(map[string]string{"X-API-Key": "k", "X-Company-Token": "t"})
		without := requestWith(map[string]string{"X-API-Key": "k"})
		require.Equal(t, string(appendDefaultKey(nil, without, &purge.cfg)), string(appendDefaultKey(nil, withToken, &purge.cfg)))
		require.False(t, purge.sends(requestWith(map[string]string{"X-Company-Token": "t"})))
		require.True(t, purge.sends(without))
	})

	t.Run("only a request that sends what the key holds spends the budget", func(t *testing.T) {
		t.Parallel()

		for _, tc := range legacyCredentials() {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				storage := newFailingCacheStorage()
				cfg := configDefault(tc.config(storage))
				purge := newLegacyPurge(&cfg, newManager(storage, true))
				require.NotNil(t, purge)

				purge.purge(requestWith(nil), false)
				purge.purge(requestWith(tc.send("")), false)
				require.Zero(t, purge.next.Load(), "nothing was spelled out in a key for a request without the credential")

				purge.purge(requestWith(tc.send("tok")), false)
				require.NotZero(t, purge.next.Load())
			})
		}
	})

	t.Run("past its budget it leaves entries to expire, and the budget refills", func(t *testing.T) {
		t.Parallel()

		for _, tc := range legacyCredentials() {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				storage := newFailingCacheStorage()
				cfg := configDefault(tc.config(storage))
				purge := newLegacyPurge(&cfg, newManager(storage, true))
				require.NotNil(t, purge)

				c := requestWith(tc.send("tok"))
				legacyBase := legacyKeyVersion + "|GET|" + string(appendDefaultKey(nil, c, &purge.cfg))
				require.Contains(t, legacyBase, tc.spelled("tok"))
				storage.data[legacyBase] = []byte("entry")

				// Spent for the next two bursts: far enough ahead that a tick of the clock changes nothing.
				purge.next.Store(int64(utils.Timestamp()) + 2*legacyProbeBurst)
				purge.purge(c, false)
				require.Contains(t, storage.data, legacyBase)

				// Paid back but for a probe: the last one is spent, and the one after is not.
				purge.next.Store(int64(utils.Timestamp()) + legacyProbeBurst - 10)
				purge.purge(c, false)
				require.NotContains(t, storage.data, legacyBase)

				// A flood leaves the budget empty only until the seconds pay it back.
				purge.next.Store(int64(utils.Timestamp()) - 100)
				for range legacyProbeBurst {
					require.True(t, purge.allow())
				}
				require.False(t, purge.allow())
			})
		}
	})
}
