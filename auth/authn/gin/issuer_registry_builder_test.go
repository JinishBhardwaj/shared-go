package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	ginprincipal "github.com/JinishBhardwaj/shared-go/auth/principal/gin"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// signedTokenWithIssuer builds a syntactically valid, HMAC-signed JWT
// carrying iss as its "iss" claim, for exercising WithIssuerValidator's
// dispatch end-to-end through the real gin middleware. As in
// authn/issuer_registry_test.go, the signature/secret is irrelevant here:
// dispatch is keyed on the unverified "iss" claim, and the mockValidator
// stubs below stand in for the real per-issuer verification a production
// caller would configure.
func signedTokenWithIssuer(t *testing.T, iss string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": iss})
	s, err := tok.SignedString([]byte("test-secret-irrelevant-to-registry-dispatch"))
	if err != nil {
		t.Fatalf("failed signing test token: %v", err)
	}
	return s
}

// TestAuthenticationBuilder_WithIssuerValidator_DispatchesByIssuer proves
// gap-analysis-final.md Tier 4 line 130's "Registry keyed by iss" end to
// end: two issuers registered on the same builder, wired into one real gin
// middleware, each route request landing on the principal for ITS OWN
// issuer's validator -- and a third, unregistered issuer being rejected
// with 401 rather than falling back to either configured validator.
func TestAuthenticationBuilder_WithIssuerValidator_DispatchesByIssuer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	valA := &mockValidator{principal: &principal.Principal{Subject: "user-a"}}
	valB := &mockValidator{principal: &principal.Principal{Subject: "user-b"}}

	middleware, err := NewBuilder().
		WithIssuerValidator("https://issuer-a.example", valA).
		WithIssuerValidator("https://issuer-b.example", valB).
		BuildMiddleware()
	if err != nil {
		t.Fatalf("unexpected error building middleware: %v", err)
	}

	r := gin.New()
	r.Use(middleware)
	r.GET("/test", func(c *gin.Context) {
		p, exists := ginprincipal.GetPrincipal(c)
		if !exists {
			c.String(http.StatusUnauthorized, "no principal")
			return
		}
		c.String(http.StatusOK, p.Subject)
	})

	doRequest := func(token string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	wA := doRequest(signedTokenWithIssuer(t, "https://issuer-a.example"))
	if wA.Code != http.StatusOK || wA.Body.String() != "user-a" {
		t.Fatalf("issuer-a request: got status=%d body=%q, want 200/user-a", wA.Code, wA.Body.String())
	}

	wB := doRequest(signedTokenWithIssuer(t, "https://issuer-b.example"))
	if wB.Code != http.StatusOK || wB.Body.String() != "user-b" {
		t.Fatalf("issuer-b request: got status=%d body=%q, want 200/user-b", wB.Code, wB.Body.String())
	}

	wUnknown := doRequest(signedTokenWithIssuer(t, "https://attacker-controlled.example"))
	if wUnknown.Code != http.StatusUnauthorized {
		t.Fatalf("unregistered-issuer request: got status=%d, want 401 (must not fall back to either registered validator)", wUnknown.Code)
	}
}
