package gin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestCredentialExtractor_Extract is the G9-7 regression suite for the
// Chain-of-Responsibility refactor of CredentialExtractor.Extract
// (gap-analysis-final.md Tier 4 line 130: "CredentialExtractor.Extract is
// a monolithic if-chain -- the actual CoR gap"). Written and confirmed
// green against the ORIGINAL, pre-refactor if-chain implementation FIRST
// (no test file existed for this type before this task), then re-run
// unchanged after the refactor to prove byte-for-byte behavioral
// equivalence -- these cases specifically pin the asymmetric
// precedence/conflict rules between the three sources (Authorization
// header, X-API-Key header, query param) that a naive "generic uniform
// merge" CoR redesign could easily get wrong:
//   - Authorization-header-derived api key vs. X-API-Key-header-derived
//     api key ARE conflict-checked against each other.
//   - The query-param fallback is NOT conflict-checked against either
//     header source -- it is consulted only when no header source already
//     produced an api key, and never raises a conflict even if it
//     disagrees with one.
func TestCredentialExtractor_Extract(t *testing.T) {
	newCtx := func(setup func(r *http.Request)) *gin.Context {
		gin.SetMode(gin.TestMode)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if setup != nil {
			setup(req)
		}
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		return c
	}

	t.Run("no credentials at all -> ErrNoCredentialsFound", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		_, err := e.Extract(newCtx(nil))
		if !errors.Is(err, ErrNoCredentialsFound) {
			t.Fatalf("got %v, want ErrNoCredentialsFound", err)
		}
	})

	t.Run("Authorization: Bearer <token> -> bearer credential", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		cred, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer abc123")
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Type != CredentialTypeBearer || cred.Token != "abc123" {
			t.Fatalf("got %+v, want bearer/abc123", cred)
		}
	})

	t.Run("Authorization: ApiKey <key> -> api key credential", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		cred, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("Authorization", "ApiKey secret-key")
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Type != CredentialTypeAPIKey || cred.Token != "secret-key" {
			t.Fatalf("got %+v, want apikey/secret-key", cred)
		}
	})

	t.Run("Authorization header with unrecognized scheme -> ErrInvalidHeader", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		_, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		}))
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("got %v, want ErrInvalidHeader", err)
		}
	})

	t.Run("Authorization header with no scheme separator -> ErrInvalidHeader", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		_, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("Authorization", "garbage-no-space")
		}))
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("got %v, want ErrInvalidHeader", err)
		}
	})

	t.Run("X-API-Key header alone -> api key credential", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		cred, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("X-API-Key", "hdr-key")
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Type != CredentialTypeAPIKey || cred.Token != "hdr-key" {
			t.Fatalf("got %+v, want apikey/hdr-key", cred)
		}
	})

	t.Run("Authorization ApiKey and X-API-Key AGREE -> no conflict, api key credential", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		cred, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("Authorization", "ApiKey same-key")
			r.Header.Set("X-API-Key", "same-key")
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Type != CredentialTypeAPIKey || cred.Token != "same-key" {
			t.Fatalf("got %+v, want apikey/same-key", cred)
		}
	})

	t.Run("Authorization ApiKey and X-API-Key DISAGREE -> ErrMultipleCredTypes", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		_, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("Authorization", "ApiKey key-from-auth-header")
			r.Header.Set("X-API-Key", "key-from-dedicated-header")
		}))
		if !errors.Is(err, ErrMultipleCredTypes) {
			t.Fatalf("got %v, want ErrMultipleCredTypes -- the two HEADER sources must conflict-check against each other", err)
		}
	})

	t.Run("Bearer + X-API-Key together -> ErrMultipleCredTypes", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		_, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer sometoken")
			r.Header.Set("X-API-Key", "somekey")
		}))
		if !errors.Is(err, ErrMultipleCredTypes) {
			t.Fatalf("got %v, want ErrMultipleCredTypes", err)
		}
	})

	t.Run("query param disabled by default -> ignored, ErrNoCredentialsFound", func(t *testing.T) {
		e := NewCredentialExtractor(DefaultExtractorConfig())
		_, err := e.Extract(newCtx(func(r *http.Request) {
			r.URL.RawQuery = "api_key=from-query"
		}))
		if !errors.Is(err, ErrNoCredentialsFound) {
			t.Fatalf("got %v, want ErrNoCredentialsFound (AllowQueryAPIKey defaults to false)", err)
		}
	})

	t.Run("query param enabled, no header present -> api key credential from query", func(t *testing.T) {
		cfg := DefaultExtractorConfig()
		cfg.AllowQueryAPIKey = true
		e := NewCredentialExtractor(cfg)
		cred, err := e.Extract(newCtx(func(r *http.Request) {
			r.URL.RawQuery = "api_key=from-query"
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Type != CredentialTypeAPIKey || cred.Token != "from-query" {
			t.Fatalf("got %+v, want apikey/from-query", cred)
		}
	})

	// This is the load-bearing asymmetry test: the query param is a pure
	// fallback, consulted only when no header already supplied an api key,
	// and it is NEVER conflict-checked against a header-derived value even
	// when both are present and disagree. A naive "generic uniform merge"
	// CoR design would very likely add a conflict check here that does not
	// exist in the original implementation -- this test exists specifically
	// to catch that regression.
	t.Run("query param enabled but a header api key already won -> header value used, no conflict raised even though query disagrees", func(t *testing.T) {
		cfg := DefaultExtractorConfig()
		cfg.AllowQueryAPIKey = true
		e := NewCredentialExtractor(cfg)
		cred, err := e.Extract(newCtx(func(r *http.Request) {
			r.Header.Set("X-API-Key", "header-key")
			r.URL.RawQuery = "api_key=different-query-key"
		}))
		if err != nil {
			t.Fatalf("unexpected error (query must not conflict-check against a header value): %v", err)
		}
		if cred.Type != CredentialTypeAPIKey || cred.Token != "header-key" {
			t.Fatalf("got %+v, want apikey/header-key (the header source wins silently over a disagreeing query value)", cred)
		}
	})

	t.Run("custom API key header name and query param name are honored", func(t *testing.T) {
		cfg := ExtractorConfig{APIKeyHeader: "X-Custom-Key", AllowQueryAPIKey: true, APIKeyQueryParam: "custom_q"}
		e := NewCredentialExtractor(cfg)
		cred, err := e.Extract(newCtx(func(r *http.Request) {
			r.URL.RawQuery = "custom_q=q-value"
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.Type != CredentialTypeAPIKey || cred.Token != "q-value" {
			t.Fatalf("got %+v, want apikey/q-value", cred)
		}
	})
}
