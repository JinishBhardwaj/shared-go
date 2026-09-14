package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestNewOIDCValidator_DiscoveryBreakerFailsFastAfterRepeatedFailures is the
// Tier 3 "breaker on OIDC discovery" regression test: repeated
// NewOIDCValidator construction attempts against the same permanently-down
// issuer must eventually fail fast (the per-issuer discovery breaker opens)
// instead of hammering .well-known/openid-configuration once per attempt
// forever.
func TestNewOIDCValidator_DiscoveryBreakerFailsFastAfterRepeatedFailures(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		http.Error(w, "discovery is down", http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx := context.Background()
	const attempts = 15
	for i := 0; i < attempts; i++ {
		if _, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
			IssuerURL:        server.URL,
			DiscoveryTimeout: 500 * time.Millisecond,
		}); err == nil {
			t.Fatalf("attempt %d: expected an error against a permanently-down discovery endpoint", i)
		}
	}

	got := atomic.LoadInt32(&requests)
	if got >= attempts {
		t.Fatalf("expected the discovery breaker to short-circuit at least some of %d attempts, but the fake discovery endpoint saw %d requests (one per attempt -- breaker never engaged)", attempts, got)
	}
	t.Logf("discovery endpoint saw %d requests across %d NewOIDCValidator attempts (breaker engaged)", got, attempts)
}

// jwksFailureServer builds a discovery + JWKS httptest server whose JWKS
// endpoint can be toggled to fail on demand, used to exercise the Tier 3
// verify-path breaker/deadline. Every issued token uses a distinct kid so
// go-oidc's remote key set cannot serve it from cache and must re-fetch the
// JWKS document on every single Verify call -- mirroring the gap analysis's
// own observation that "random-kid tokens amplify into JWKS traffic."
type jwksFailureServer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey

	failing    atomic.Bool
	blockDelay atomic.Int64 // nanoseconds; if >0, jwks.json blocks this long before responding
	jwksHits   atomic.Int32
}

func newJWKSFailureServer(t *testing.T) *jwksFailureServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	f := &jwksFailureServer{privateKey: key}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                f.server.URL,
				"jwks_uri":                              f.server.URL + "/jwks.json",
				"response_types_supported":              []string{"code", "token", "id_token"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks.json":
			f.jwksHits.Add(1)
			if d := f.blockDelay.Load(); d > 0 {
				select {
				case <-time.After(time.Duration(d)):
				case <-r.Context().Done():
					return
				}
			}
			if f.failing.Load() {
				http.Error(w, "jwks is down", http.StatusInternalServerError)
				return
			}
			nStr := base64.RawURLEncoding.EncodeToString(f.privateKey.N.Bytes())
			eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.privateKey.E)).Bytes())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "kid-0", "n": nStr, "e": eStr},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *jwksFailureServer) tokenWithUnknownKid(t *testing.T, n int) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": f.server.URL,
		"sub": "user-1",
		"aud": "any",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	// A distinct, never-valid kid on every call forces go-oidc's remote key
	// set to treat every token as "unknown kid" and re-fetch JWKS rather
	// than serving from its own cache.
	token.Header["kid"] = "unknown-kid-" + time.Now().Format("150405.000000000") + "-" + string(rune('a'+n%26))
	s, err := token.SignedString(f.privateKey)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return s
}

// TestOIDCValidator_VerifyBreakerFailsFastAfterRepeatedFailures is the
// Tier 3 "breaker on JWKS fetch" regression test.
func TestOIDCValidator_VerifyBreakerFailsFastAfterRepeatedFailures(t *testing.T) {
	f := newJWKSFailureServer(t)
	ctx := context.Background()

	validator, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:         f.server.URL,
		SkipClientIDCheck: true,
		VerifyTimeout:     500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewOIDCValidator: %v", err)
	}

	f.failing.Store(true)

	const attempts = 15
	for i := 0; i < attempts; i++ {
		tok := f.tokenWithUnknownKid(t, i)
		if _, err := validator.ValidateToken(ctx, tok); err == nil {
			t.Fatalf("attempt %d: expected validation to fail against a permanently-down JWKS endpoint", i)
		}
	}

	got := f.jwksHits.Load()
	if got >= attempts {
		t.Fatalf("expected the verify breaker to short-circuit at least some of %d attempts, but the fake JWKS endpoint saw %d hits (breaker never engaged)", attempts, got)
	}
	t.Logf("jwks endpoint saw %d hits across %d ValidateToken attempts (breaker engaged)", got, attempts)
}

// TestOIDCValidator_VerifyTimeout_BoundsASlowJWKSFetch proves VerifyTimeout
// actually bounds a slow/unresponsive JWKS endpoint instead of letting
// ValidateToken hang, and that a deadline-exceeded fetch is treated as a
// validation failure -- never as an accepted token. This is the fail-closed
// proof for this item.
func TestOIDCValidator_VerifyTimeout_BoundsASlowJWKSFetch(t *testing.T) {
	f := newJWKSFailureServer(t)
	ctx := context.Background()

	validator, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:         f.server.URL,
		SkipClientIDCheck: true,
		VerifyTimeout:     50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewOIDCValidator: %v", err)
	}

	f.blockDelay.Store(int64(2 * time.Second))
	tok := f.tokenWithUnknownKid(t, 0)

	start := time.Now()
	_, err = validator.ValidateToken(ctx, tok)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected a deadline-exceeded JWKS fetch to be treated as a validation failure, got a successfully validated token")
	}
	if elapsed > time.Second {
		t.Fatalf("ValidateToken took %v -- VerifyTimeout does not appear to be bounding the underlying JWKS fetch", elapsed)
	}
}
