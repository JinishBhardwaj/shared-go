package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// validTokenWithKnownKid signs a token with "kid-0", the kid jwksFailureServer
// always serves in its JWKS document (see newJWKSFailureServer) -- the
// counterpart to tokenWithUnknownKid, which deliberately never matches it.
func (f *jwksFailureServer) validTokenWithKnownKid(t *testing.T) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": f.server.URL,
		"sub": "user-1",
		"aud": "any",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "kid-0"
	s, err := token.SignedString(f.privateKey)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return s
}

// --- kidGate unit tests -----------------------------------------------

func TestKidGate_UnknownKidAllowedUntilBucketExhausted(t *testing.T) {
	g := newKidGate(30*time.Second, 0 /* ratePerSec: use default won't matter, we pass explicit burst */, 2)
	// Force a tiny, deterministic bucket for this test regardless of
	// defaults: rebuild with an explicit low rate/burst.
	g = newKidGate(30*time.Second, 0.0001, 2)
	now := time.Now()

	if ok, _ := g.allow("kid-a", now); !ok {
		t.Fatalf("first request for a brand-new kid should be allowed")
	}
	if ok, _ := g.allow("kid-b", now); !ok {
		t.Fatalf("second request (still within burst of 2) should be allowed")
	}
	if ok, reason := g.allow("kid-c", now); ok {
		t.Fatalf("third request should be rate-limited (burst exhausted), got allowed with no reason")
	} else if reason == "" {
		t.Fatalf("expected a non-empty reason for a rate-limited request")
	}
}

func TestKidGate_KnownGoodKidNeverRateLimited(t *testing.T) {
	// Burst of 0 effectively (rate so low it never refills within the
	// test), so ANY unknown kid would be rejected immediately.
	g := newKidGate(30*time.Second, 0.00001, 1)
	now := time.Now()

	// Consume the only token so the bucket is empty.
	if ok, _ := g.allow("burns-the-only-token", now); !ok {
		t.Fatalf("setup: expected the first (burst=1) request to be allowed")
	}
	g.markBad("burns-the-only-token", now) // this kid never succeeded; leave it as a normal failed kid

	// Mark a DIFFERENT kid known-good directly (simulating a prior
	// successful verify), then hammer allow() for it many times: none of
	// this may ever be denied, no matter how exhausted the shared bucket
	// is for everyone else.
	g.markGood("the-real-key")
	for i := 0; i < 50; i++ {
		if ok, reason := g.allow("the-real-key", now); !ok {
			t.Fatalf("iteration %d: a known-good kid must never be rate-limited or negative-cached, got denied: %s", i, reason)
		}
	}
}

func TestKidGate_NegativeCacheExpiresAfterTTL(t *testing.T) {
	g := newKidGate(10*time.Millisecond, 1000, 1000) // generous rate limiter; isolate the TTL behavior
	now := time.Now()

	g.markBad("bad-kid", now)
	if ok, _ := g.allow("bad-kid", now); ok {
		t.Fatalf("a kid that just failed must be denied within the negative-cache TTL")
	}
	later := now.Add(11 * time.Millisecond)
	if ok, _ := g.allow("bad-kid", later); !ok {
		t.Fatalf("a kid whose negative-cache entry has aged out past the TTL must be allowed again")
	}
}

func TestKidGate_MarkGoodClearsAnyPriorNegativeEntry(t *testing.T) {
	g := newKidGate(time.Hour, 1000, 1000)
	now := time.Now()
	g.markBad("kid-x", now)
	if ok, _ := g.allow("kid-x", now); ok {
		t.Fatalf("setup: expected kid-x to be negative-cached")
	}
	g.markGood("kid-x")
	if ok, _ := g.allow("kid-x", now); !ok {
		t.Fatalf("markGood must clear a prior negative-cache entry immediately, not wait out the TTL")
	}
}

func TestKidGate_MarkBadOnAKnownGoodKidDemotesItWithoutNegativeCaching(t *testing.T) {
	// A kid that was good and then fails (e.g. transient breaker-open,
	// or key rotated out) must re-enter the ordinary gate, NOT be
	// poisoned into the negative cache on the strength of one failure of
	// a key that was, until a moment ago, genuinely valid.
	g := newKidGate(time.Hour, 1000, 1000)
	now := time.Now()
	g.markGood("kid-y")
	g.markBad("kid-y", now)
	if ok, _ := g.allow("kid-y", now); !ok {
		t.Fatalf("a demoted (formerly-good) kid must still be allowed through the ordinary gate immediately after one failure, not negative-cached")
	}
}

// --- integration tests against a real OIDCValidator --------------------

// TestOIDCValidator_JWKSHardening_UnknownKidFloodIsRateLimited is the Tier 3
// "rate-limit refetch on unknown kid" regression test: a flood of tokens
// carrying distinct, never-repeated kids against a down JWKS endpoint must
// not each individually reach the JWKS endpoint -- the token-bucket rate
// limiter must bound how many of them do.
func TestOIDCValidator_JWKSHardening_UnknownKidFloodIsRateLimited(t *testing.T) {
	f := newJWKSFailureServer(t)
	ctx := context.Background()

	validator, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:             f.server.URL,
		SkipClientIDCheck:     true,
		VerifyTimeout:         500 * time.Millisecond,
		KidRateLimitPerSecond: 0.001, // effectively no refill within this test
		KidRateLimitBurst:     3,
	})
	if err != nil {
		t.Fatalf("NewOIDCValidator: %v", err)
	}
	f.failing.Store(true)

	const attempts = 20
	for i := 0; i < attempts; i++ {
		tok := f.tokenWithUnknownKid(t, i)
		if _, err := validator.ValidateToken(ctx, tok); err == nil {
			t.Fatalf("attempt %d: expected failure against a down JWKS endpoint", i)
		}
	}

	got := f.jwksHits.Load()
	if got > 3 {
		t.Fatalf("expected the unknown-kid rate limiter (burst=3) to bound JWKS hits to at most 3 across %d distinct-kid attempts, got %d", attempts, got)
	}
	t.Logf("jwks endpoint saw %d hits across %d distinct-unknown-kid attempts (rate limiter engaged)", got, attempts)
}

// TestOIDCValidator_JWKSHardening_RepeatedSameFailedKidDoesNotRefetch is the
// Tier 3 "negative-kid cache" regression test: retrying the SAME kid that
// just failed a real key-resolution attempt must be short-circuited without
// hitting the JWKS endpoint again, within the negative-cache window.
func TestOIDCValidator_JWKSHardening_RepeatedSameFailedKidDoesNotRefetch(t *testing.T) {
	f := newJWKSFailureServer(t)
	ctx := context.Background()

	validator, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:           f.server.URL,
		SkipClientIDCheck:   true,
		VerifyTimeout:       500 * time.Millisecond,
		NegativeKidCacheTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewOIDCValidator: %v", err)
	}
	f.failing.Store(true)

	tok := f.tokenWithUnknownKid(t, 0)
	if _, err := validator.ValidateToken(ctx, tok); err == nil {
		t.Fatalf("expected the first attempt to fail against a down JWKS endpoint")
	}
	hitsAfterFirst := f.jwksHits.Load()
	if hitsAfterFirst == 0 {
		t.Fatalf("expected the first attempt for a brand-new kid to actually reach the JWKS endpoint")
	}

	// Retry the exact same token (same kid) several times: none of these
	// may reach the JWKS endpoint again while the negative-cache entry is
	// live.
	for i := 0; i < 5; i++ {
		if _, err := validator.ValidateToken(ctx, tok); err == nil {
			t.Fatalf("retry %d: expected failure (kid should still be negative-cached)", i)
		}
	}
	if got := f.jwksHits.Load(); got != hitsAfterFirst {
		t.Fatalf("expected zero additional JWKS hits for repeated attempts on the same already-failed kid within the negative-cache window; hits went from %d to %d", hitsAfterFirst, got)
	}
}

// TestOIDCValidator_JWKSHardening_KnownGoodKidNeverCollaterallyBlocked is the
// critical fail-closed-in-the-right-direction proof: a real, correctly
// signed, already-validated kid must keep validating successfully even
// while a flood of unrelated unknown-kid traffic exhausts the rate limiter
// on the same validator instance.
func TestOIDCValidator_JWKSHardening_KnownGoodKidNeverCollaterallyBlocked(t *testing.T) {
	f := newJWKSFailureServer(t)
	ctx := context.Background()

	validator, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:             f.server.URL,
		SkipClientIDCheck:     true,
		VerifyTimeout:         500 * time.Millisecond,
		KidRateLimitPerSecond: 0.001,
		KidRateLimitBurst:     1,
	})
	if err != nil {
		t.Fatalf("NewOIDCValidator: %v", err)
	}

	realToken := f.validTokenWithKnownKid(t)
	if _, err := validator.ValidateToken(ctx, realToken); err != nil {
		t.Fatalf("expected the real, correctly-signed token to validate successfully first, got %v", err)
	}

	// Now exhaust the rate limiter (burst=1, already consumed by the real
	// token's own first-ever pass through the gate) with unrelated garbage
	// kids against a down JWKS endpoint.
	f.failing.Store(true)
	for i := 0; i < 10; i++ {
		_, _ = validator.ValidateToken(ctx, f.tokenWithUnknownKid(t, i))
	}

	// The known-good kid must keep validating successfully throughout --
	// flip the JWKS endpoint back to healthy first only to prove the
	// SIGNATURE still checks out; the gate itself must not be the reason
	// a retry of the same real token would ever fail.
	f.failing.Store(false)
	for i := 0; i < 5; i++ {
		if _, err := validator.ValidateToken(ctx, realToken); err != nil {
			t.Fatalf("iteration %d: known-good kid must never be collaterally rate-limited or negative-cached by unrelated unknown-kid traffic, got %v", i, err)
		}
	}
}

// TestOIDCValidator_JWKSHardening_ClaimsFailureNeverPoisonsKid is the
// regression test for the false-positive this implementation was caught
// producing during development: go-oidc checks claims (audience, issuer,
// expiry) BEFORE ever touching the key set, so a claims-level failure (e.g.
// audience mismatch) must NEVER negative-cache the kid -- doing so would
// falsely block the next, otherwise-valid token signed by the exact same
// good key.
func TestOIDCValidator_JWKSHardening_ClaimsFailureNeverPoisonsKid(t *testing.T) {
	server, privateKey, kid := newMockOIDCServer(t)

	validator, err := NewOIDCValidator(context.Background(), OIDCValidatorConfig{
		IssuerURL:        server.URL,
		ExpectedClientID: "the-real-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCValidator: %v", err)
	}

	now := time.Now()
	claimsWithAudience := func(aud string) jwt.MapClaims {
		return jwt.MapClaims{
			"iss": server.URL,
			"sub": "user-1",
			"aud": aud,
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
		}
	}

	wrongAudienceToken := signMockOIDCToken(t, privateKey, kid, claimsWithAudience("wrong-client"))
	if _, err := validator.ValidateToken(context.Background(), wrongAudienceToken); err == nil {
		t.Fatalf("expected the wrong-audience token to fail validation")
	}

	rightAudienceToken := signMockOIDCToken(t, privateKey, kid, claimsWithAudience("the-real-client"))
	if _, err := validator.ValidateToken(context.Background(), rightAudienceToken); err != nil {
		t.Fatalf("a valid token sharing the SAME kid as a prior claims-only failure must still validate; the kid must never have been negative-cached for a claims failure, got %v", err)
	}
}

// --- discovery retry-with-backoff ---------------------------------------

// TestNewOIDCValidator_DiscoveryRetryRecoversFromTransientFailures is the
// Tier 3 "retry OIDC discovery with exponential backoff instead of failing
// boot" regression test: a discovery endpoint that fails a bounded number
// of times and then succeeds must be recovered by the retry loop, where a
// single-attempt caller (DiscoveryRetryAttempts: 1) would fail outright.
func TestNewOIDCValidator_DiscoveryRetryRecoversFromTransientFailures(t *testing.T) {
	var hits atomic.Int32
	const failFirstN = 2

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n <= failFirstN {
			http.Error(w, "discovery temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                server.URL,
			"jwks_uri":                              server.URL + "/jwks.json",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{}})
	})

	t.Run("single attempt fails against a transiently-down endpoint", func(t *testing.T) {
		hits.Store(0)
		_, err := NewOIDCValidator(context.Background(), OIDCValidatorConfig{
			IssuerURL:              server.URL,
			DiscoveryTimeout:       500 * time.Millisecond,
			DiscoveryRetryAttempts: 1,
		})
		if err == nil {
			t.Fatalf("expected a single discovery attempt to fail while the endpoint is still returning 503s")
		}
	})

	t.Run("bounded retry recovers", func(t *testing.T) {
		hits.Store(0)
		v, err := NewOIDCValidator(context.Background(), OIDCValidatorConfig{
			IssuerURL:              server.URL,
			DiscoveryTimeout:       500 * time.Millisecond,
			DiscoveryRetryAttempts: failFirstN + 2,
			DiscoveryRetryBackoff:  5 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("expected the retry loop to recover after %d transient failures, got %v", failFirstN, err)
		}
		if v == nil {
			t.Fatalf("expected a non-nil validator on recovery")
		}
	})
}
