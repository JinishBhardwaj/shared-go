package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type mockValidator struct {
	principal *Principal
}

func (m *mockValidator) ValidateToken(ctx context.Context, tokenStr string) (*Principal, error) {
	return m.principal, nil
}

type testClaimsTransformer struct{}

func (t *testClaimsTransformer) Transform(ctx context.Context, p *Principal) (*Principal, error) {
	if p.Metadata == nil {
		p.Metadata = make(map[string]any)
	}
	p.Metadata["transformed"] = true
	return p, nil
}

func TestAuthenticationBuilder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	val := &mockValidator{
		principal: &Principal{
			Subject:  "user_123",
			Method:   AuthMethodAuthCodePKCE,
			Roles:    []string{"admin"},
			Metadata: make(map[string]any),
		},
	}

	middleware, err := NewBuilder().
		WithBearerValidator(val).
		WithClaimsTransformation(&testClaimsTransformer{}).
		BuildMiddleware()

	if err != nil {
		t.Fatalf("unexpected error building middleware: %v", err)
	}

	r := gin.New()
	r.Use(middleware)
	r.GET("/test", func(c *gin.Context) {
		p, exists := GetPrincipal(c)
		if !exists {
			c.String(http.StatusUnauthorized, "no principal")
			return
		}
		if p.Metadata["transformed"] != true {
			c.String(http.StatusInternalServerError, "not transformed")
			return
		}
		c.String(http.StatusOK, p.Subject)
	})

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer dummy-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "user_123" {
		t.Errorf("expected subject user_123, got %s", w.Body.String())
	}
}
