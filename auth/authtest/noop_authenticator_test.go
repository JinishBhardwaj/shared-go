package authtest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/gin-gonic/gin"
)

func TestNewNoopAuthenticator_NilPrincipal(t *testing.T) {
	_, err := NewNoopAuthenticator(nil)
	if err != ErrNilPrincipal {
		t.Fatalf("expected ErrNilPrincipal, got %v", err)
	}
}

func TestNoopAuthenticator_ReturnsFixedPrincipalRegardlessOfRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	want := &principal.Principal{Subject: "dev-user", Roles: []string{"admin"}}
	auth, err := NewNoopAuthenticator(want)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No Authorization header, no credentials of any kind -- Authenticate
	// must still succeed with the configured principal.
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	got, err := auth.Authenticate(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("expected same *principal.Principal instance back, got %v", got)
	}
}
