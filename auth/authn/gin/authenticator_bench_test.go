package gin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authn/bearer"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// BenchmarkCompositeAuthenticator_Authenticate_Bearer is the Tier 3
// baseline benchmark for CompositeAuthenticator.Authenticate on the Bearer
// JWT path (gap-analysis-final.md: "Benchmarks for Authenticate,
// PolicyEngine.Authorize and PARC evaluation -- establish baselines before
// optimizing, and to prove the claims above"). A single real, valid,
// non-expired HS256 JWT is signed once outside the timed loop; only a fresh
// *gin.Context (and its underlying request) is rebuilt per iteration, since
// that is what a real inbound request looks like -- the token itself is
// never re-signed inside the loop.
func BenchmarkCompositeAuthenticator_Authenticate_Bearer(b *testing.B) {
	hmacKey := []byte("bench-hmac-secret-key")

	validator, err := bearer.NewJWTValidator(bearer.JWTValidatorConfig{
		KeyFunc: func(token *jwt.Token) (any, error) {
			return hmacKey, nil
		},
		AllowedSigningAlgs: []string{"HS256"},
	})
	if err != nil {
		b.Fatalf("failed to create JWTValidator: %v", err)
	}

	claims := jwt.MapClaims{
		"sub": "bench-user",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	signedToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(hmacKey)
	if err != nil {
		b.Fatalf("failed to sign benchmark JWT: %v", err)
	}

	auth := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		ExtractorConfig: DefaultExtractorConfig(),
		JWTValidator:    validator,
	})

	gin.SetMode(gin.TestMode)

	newBenchGinContext := func() *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+signedToken)
		c.Request = req
		return c
	}

	// Sanity check once before timing: a setup mistake here (e.g. a bad
	// signing key or clock skew) must fail loudly, not just make the
	// benchmark measure the error path.
	if _, err := auth.Authenticate(newBenchGinContext()); err != nil {
		b.Fatalf("sanity Authenticate call failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := newBenchGinContext()
		if _, err := auth.Authenticate(c); err != nil {
			b.Fatal(err)
		}
	}
}
