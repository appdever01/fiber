package cache

import (
	"sync/atomic"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/internal/fieldname"
	"github.com/gofiber/fiber/v3/internal/headerlookup"
	"github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/utils/v2"
)

// legacyKeyVersion is the key version before credential values were hashed in the key. Its
// entries are never read but still spell a credential out in an external Storage's keys until
// they expire; legacyPurge ends that for clients that return. Delete this file once none remain.
const legacyKeyVersion = "v4"

// Purging adds a bounded amount of work: a burst of legacyProbeBurst probes, then one more each
// second. What is left meanwhile is left to expire, as it would have without the purge.
const legacyProbeBurst = 1024

// legacyPurge deletes what the previous key version stored for a request, found by keying it
// as that version did. A Storage cannot list its keys, so this reaches only the credentials
// that return; the rest expire on their own.
type legacyPurge struct {
	m       *manager
	headers []string     // the credential headers that version kept in the key
	cfg     Config       // keys as the previous version did, credential values spelled out
	next    atomic.Int64 // the second the probes spent so far are paid back by
}

// newLegacyPurge returns nil when there is nothing to purge: an in-memory store does not
// outlive the process, a custom KeyGenerator's key never held the credential, and a key
// without a credential header or cookie spells none.
func newLegacyPurge(cfg *Config, m *manager) *legacyPurge {
	if cfg.Storage == nil || !cfg.usesDefaultKeyGenerator {
		return nil
	}
	headers := cfg.appendCredentials(nil, cfg.plainKeyHeaders)
	if len(headers) == 0 && len(cfg.KeyCookies) == 0 {
		return nil
	}
	previous := *cfg
	previous.KeyHeaders = cfg.plainKeyHeaders // without KeyCredentialHeaders, which that version lacked
	previous.credentialKeyHeaders = nil
	previous.spellCookies = true
	return &legacyPurge{m: m, cfg: previous, headers: headers}
}

// sends reports whether the request sends a credential that version spelled out in its key.
func (p *legacyPurge) sends(c fiber.Ctx) bool {
	for _, name := range p.cfg.KeyCookies {
		if c.Cookies(name) != "" {
			return true
		}
	}
	return hasHeaderValue(c, p.headers)
}

// allow spends a probe, if the budget has one. It refills a probe a second, so a flood of requests
// can use the budget up but not end the purge.
func (p *legacyPurge) allow() bool {
	now := int64(utils.Timestamp())
	for {
		spent := p.next.Load()
		due := max(spent, now)
		if due-now >= legacyProbeBurst {
			return false
		}
		if p.next.CompareAndSwap(spent, due+1) {
			return true
		}
	}
}

// purge deletes the entry, body, Vary manifest and variant the previous version stored for
// the request, if it sends a credential the key holds.
func (p *legacyPurge) purge(c fiber.Ctx, hasAuthorization bool) { //nolint:revive // flag-parameter: a property of the request, not a mode of operation
	if p == nil || !p.sends(c) || !p.allow() {
		return
	}

	canonical := headerlookup.Canonical(c)
	bufPtr := acquireKeyBuffer()
	buf := (*bufPtr)[:0]
	buf = append(buf, legacyKeyVersion...)
	buf = append(buf, '|')
	buf = append(buf, c.Method()...)
	buf = append(buf, '|')
	buf = appendDefaultKey(buf, c, &p.cfg)
	if hasAuthorization {
		buf = append(buf, "|auth="...)
		buf = appendAuthHash(buf, fieldname.Lines(&c.Request().Header, fiber.HeaderAuthorization, canonical))
	}
	base := string(buf)
	releaseKeyBuffer(bufPtr, buf)

	keys := []string{base, base + "_body"}
	manifestKey := base + "|vary"
	ctx := c.Context()
	if names, found, err := loadVaryManifest(ctx, p.m, manifestKey); err == nil && found {
		variant := varyKey(base, names, &c.Request().Header, canonical)
		keys = append(keys, manifestKey, variant, variant+"_body")
	}
	for _, key := range keys {
		if err := p.m.del(ctx, key); err != nil {
			log.Warnf("cache: failed to purge an entry of the previous key version: %v", err)
		}
	}
}
