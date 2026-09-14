package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/JinishBhardwaj/shared-go/cache"
	"github.com/JinishBhardwaj/shared-go/cache/memory"
)

// TokenValidator is the minimal shape both JWTValidator and OIDCValidator
// already satisfy (ValidateToken(ctx, tokenStr) (*principal.Principal,
// error)) -- duck-typed here, deliberately not shared with authn/gin's own
// BearerTokenValidator interface (same signature), so this package never
// imports gin. Any BearerTokenValidator from authn/gin structurally
// satisfies this too, and vice versa.
type TokenValidator interface {
	ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error)
}

// CachingValidatorConfig configures CachingValidator.
type CachingValidatorConfig struct {
	// Cache backs the verified-token cache. Defaults to an in-process
	// memory.Store[*principal.Principal] if nil.
	Cache cache.Cache[*principal.Principal]

	// MaxTTL upper-bounds how long a validated result may be cached,
	// regardless of the token's own exp. Defaults to 5 minutes. A result
	// is never cached longer than the token's own remaining lifetime
	// (time.Until(principal.ExpiresAt)) even if MaxTTL is larger -- see
	// ValidateToken's doc comment.
	MaxTTL time.Duration
}

// CachingValidator wraps a TokenValidator (JWTValidator, OIDCValidator, or
// any caller-supplied validator) with a verified-token cache keyed on a
// hash of the raw token string (Tier 3 gap-analysis-final.md line 120:
// "Verified-token cache keyed on a hash of the token, bounded by the
// token's own exp — saves an RSA verify (~50–100µs) per request").
//
// Fail-closed analysis (required for anything caching an authentication
// outcome): this introduces no new revocation gap. There is no live JWT
// revocation/denylist mechanism anywhere in this codebase today (a `jti`
// replay denylist is explicitly named as optional, deferred Tier 4
// hardening in gap-analysis-final.md) -- a validated token is already
// treated as valid until its own natural exp with or without this cache.
// The cache only ever narrows the window in which a repeat verification of
// the SAME token string is skipped, and that window is capped at the
// token's own exp (never later), so it cannot serve a decision past the
// point the un-cached path would also have accepted it.
type CachingValidator struct {
	inner  TokenValidator
	cache  cache.Cache[*principal.Principal]
	maxTTL time.Duration
}

// NewCachingValidator wraps inner with a verified-token cache.
func NewCachingValidator(inner TokenValidator, cfg CachingValidatorConfig) *CachingValidator {
	c := cfg.Cache
	if c == nil {
		c = memory.New[*principal.Principal](0)
	}
	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = 5 * time.Minute
	}
	return &CachingValidator{
		inner:  inner,
		cache:  c,
		maxTTL: maxTTL,
	}
}

// tokenCacheKey hashes tokenStr rather than using it directly as the cache
// key, so the raw credential is never present in the cache's own key
// space (relevant if the cache backend is ever inspectable, e.g. logged or
// backed by a shared store) -- this is not a secrecy/timing control (cache
// key lookups are not a place a timing side channel against the token's
// value would be meaningful), just defense in depth against incidental
// exposure.
func tokenCacheKey(tokenStr string) string {
	sum := sha256.Sum256([]byte(tokenStr))
	return "authn:tokv1:" + hex.EncodeToString(sum[:])
}

// ValidateToken returns a cached result for tokenStr if one is present and
// still within its cached lifetime; otherwise it delegates to the inner
// validator and, on success, caches the result for
// min(MaxTTL, time.Until(principal.ExpiresAt)).
//
// A cache Get error (a real cache failure, never a plain miss per
// cache.Cache[T]'s own contract) degrades to calling the inner validator
// directly, the same graceful-degradation shape PARCHandler already uses
// for its own cache -- a degraded cache must never take authentication
// down with it, and must never be treated as an authoritative "not
// cached, so deny" signal either.
//
// A failed inner validation is NEVER cached, in either direction: it is
// not remembered as "this token is valid" (obviously), and it is not
// remembered as "this token is permanently invalid" either -- a
// transiently-failing validator (e.g. a momentary JWKS fetch error) must
// be retried on the next call, not have its failure pinned for MaxTTL.
//
// A successful result with no ExpiresAt set and no configured MaxTTL
// override is never cached (caching with no bound at all would defeat the
// entire "bounded by the token's own exp" requirement); a result that is
// already expired by the time ValidateToken returns (should not happen --
// the inner validator is expected to reject expired tokens itself -- but
// checked defensively) is likewise never cached.
func (v *CachingValidator) ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error) {
	key := tokenCacheKey(tokenStr)

	if cached, found, err := v.cache.Get(ctx, key); err == nil && found && cached != nil {
		return cached, nil
	}

	p, err := v.inner.ValidateToken(ctx, tokenStr)
	if err != nil {
		return nil, err
	}
	if p == nil {
		// Defensive: CachingValidator wraps ANY caller-supplied
		// TokenValidator, not just the two in-tree implementations (which
		// never return (nil, nil) -- traced through JWTValidator,
		// OIDCValidator, and both ClaimsNormalizers). A validator that
		// violates its own contract this way must not be cached or
		// dereferenced; return it unchanged rather than panic.
		return nil, nil
	}

	ttl := v.maxTTL
	if !p.ExpiresAt.IsZero() {
		untilExp := time.Until(p.ExpiresAt)
		if untilExp <= 0 {
			// Already expired by the time we got here -- do not cache a
			// result that is stale on arrival.
			return p, nil
		}
		if ttl <= 0 || untilExp < ttl {
			ttl = untilExp
		}
	} else if ttl <= 0 {
		// No exp claim on the token and no configured MaxTTL fallback:
		// caching with no bound at all is exactly the thing this feature
		// must never do.
		return p, nil
	}

	_ = v.cache.Set(ctx, key, p, ttl)
	return p, nil
}
