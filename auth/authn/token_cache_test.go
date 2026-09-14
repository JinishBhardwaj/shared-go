package authn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

// countingValidator is a configurable TokenValidator stub used to prove
// CachingValidator's cache-hit/miss/error behavior without a real JWT/OIDC
// validator.
type countingValidator struct {
	mu    sync.Mutex
	calls int
	// result(tokenStr) is called on every invocation, so tests can vary
	// the returned Principal/error per call (e.g. to prove errors are
	// never cached).
	result func(tokenStr string) (*principal.Principal, error)
}

func (c *countingValidator) ValidateToken(_ context.Context, tokenStr string) (*principal.Principal, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.result(tokenStr)
}

func (c *countingValidator) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestCachingValidator_CacheHit_SkipsInnerValidator(t *testing.T) {
	inner := &countingValidator{
		result: func(tokenStr string) (*principal.Principal, error) {
			return &principal.Principal{Subject: "u1", ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	v := NewCachingValidator(inner, CachingValidatorConfig{})
	ctx := context.Background()

	p1, err := v.ValidateToken(ctx, "token-a")
	if err != nil || p1 == nil || p1.Subject != "u1" {
		t.Fatalf("unexpected first call result: %+v, err=%v", p1, err)
	}
	if _, err := v.ValidateToken(ctx, "token-a"); err != nil {
		t.Fatalf("unexpected second call error: %v", err)
	}
	if _, err := v.ValidateToken(ctx, "token-a"); err != nil {
		t.Fatalf("unexpected third call error: %v", err)
	}

	if got := inner.callCount(); got != 1 {
		t.Errorf("expected the inner validator to be called exactly once (cache hit on calls 2 and 3), got %d calls", got)
	}
}

func TestCachingValidator_TTLBoundedByTokenExpiry_NotByConfiguredMax(t *testing.T) {
	// ExpiresAt is far sooner than the configured MaxTTL: the cache entry
	// must expire (and the inner validator must be re-consulted) once the
	// TOKEN's own exp has passed, not wait for the much longer MaxTTL.
	inner := &countingValidator{
		result: func(tokenStr string) (*principal.Principal, error) {
			return &principal.Principal{Subject: "u1", ExpiresAt: time.Now().Add(30 * time.Millisecond)}, nil
		},
	}
	v := NewCachingValidator(inner, CachingValidatorConfig{MaxTTL: time.Hour})
	ctx := context.Background()

	if _, err := v.ValidateToken(ctx, "token-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := v.ValidateToken(ctx, "token-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := inner.callCount(); got != 1 {
		t.Fatalf("expected 1 call before expiry (cache hit), got %d", got)
	}

	time.Sleep(60 * time.Millisecond) // past the token's own 30ms exp

	if _, err := v.ValidateToken(ctx, "token-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := inner.callCount(); got != 2 {
		t.Errorf("expected the cache entry to have expired at the TOKEN's own exp (30ms), well before the configured 1h MaxTTL, forcing a second inner call; got %d calls", got)
	}
}

func TestCachingValidator_InnerErrorNeverCached(t *testing.T) {
	wantErr := errors.New("boom: transient validation failure")
	inner := &countingValidator{
		result: func(tokenStr string) (*principal.Principal, error) {
			return nil, wantErr
		},
	}
	v := NewCachingValidator(inner, CachingValidatorConfig{})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := v.ValidateToken(ctx, "token-a"); !errors.Is(err, wantErr) {
			t.Fatalf("call %d: expected the error to propagate, got %v", i, err)
		}
	}

	if got := inner.callCount(); got != 3 {
		t.Errorf("expected every call to reach the inner validator (a failure must never be cached as a fixed result, positive or negative), got %d calls for 3 attempts", got)
	}
}

func TestCachingValidator_DifferentTokensDontCollide(t *testing.T) {
	inner := &countingValidator{
		result: func(tokenStr string) (*principal.Principal, error) {
			return &principal.Principal{Subject: tokenStr, ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	v := NewCachingValidator(inner, CachingValidatorConfig{})
	ctx := context.Background()

	pA, err := v.ValidateToken(ctx, "token-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pB, err := v.ValidateToken(ctx, "token-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pA.Subject != "token-a" || pB.Subject != "token-b" {
		t.Fatalf("expected distinct results for distinct tokens, got %+v / %+v", pA, pB)
	}
	// Re-fetch both -- must be cache hits, not a third/fourth inner call.
	if _, err := v.ValidateToken(ctx, "token-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := v.ValidateToken(ctx, "token-b"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := inner.callCount(); got != 2 {
		t.Errorf("expected exactly 2 inner calls (one per distinct token, cached thereafter), got %d", got)
	}
}

// TestCachingValidator_ZeroExpiresAt_StillBoundedByDefaultMaxTTL confirms a
// result with no ExpiresAt claim at all is still cached under the
// constructor's default MaxTTL bound (5 minutes), rather than treated as
// "uncacheable" or, worse, cached with no bound at all. NewCachingValidator
// always substitutes a positive default MaxTTL when the caller leaves it
// unset, so there is no way to reach ValidateToken with both signals
// absent through the public constructor -- this test pins that default-
// substitution behavior so it can't silently regress into "never bounded".
func TestCachingValidator_ZeroExpiresAt_StillBoundedByDefaultMaxTTL(t *testing.T) {
	inner := &countingValidator{
		result: func(tokenStr string) (*principal.Principal, error) {
			return &principal.Principal{Subject: "u1"}, nil // zero ExpiresAt
		},
	}
	v := NewCachingValidator(inner, CachingValidatorConfig{})
	if v.maxTTL <= 0 {
		t.Fatalf("expected NewCachingValidator to substitute a positive default MaxTTL, got %v", v.maxTTL)
	}
	ctx := context.Background()

	if _, err := v.ValidateToken(ctx, "token-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := v.ValidateToken(ctx, "token-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := inner.callCount(); got != 1 {
		t.Errorf("expected a zero-ExpiresAt result to still be cached under the default MaxTTL bound (1 inner call, second is a hit), got %d", got)
	}
}
