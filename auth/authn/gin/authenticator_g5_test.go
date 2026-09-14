package gin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/gin-gonic/gin"
)

// fakeBearerValidator is a minimal BearerTokenValidator stub used to drive
// CompositeAuthenticator.Authenticate deterministically (success/failure)
// without needing real JWT/OIDC machinery, for the Tier 4 OnAuthenticate
// hook regression tests below.
type fakeBearerValidator struct {
	err error
}

func (f *fakeBearerValidator) ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &principal.Principal{Subject: "user-1"}, nil
}

func newTestGinContext(bearerToken string) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	c.Request = req
	return c
}

// TestCompositeAuthenticator_OnAuthenticate_ReportsSuccessAndFailure is the
// Tier 4 additive-instrumentation regression test for the OnAuthenticate
// hook: it must fire once per Authenticate call, reporting the credential
// type and whether the call succeeded, and must never change what
// Authenticate itself returns.
func TestCompositeAuthenticator_OnAuthenticate_ReportsSuccessAndFailure(t *testing.T) {
	var events []AuthEvent

	successAuth := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		ExtractorConfig: DefaultExtractorConfig(),
		BearerValidator: &fakeBearerValidator{},
		OnAuthenticate: func(_ context.Context, evt AuthEvent) {
			events = append(events, evt)
		},
	})

	p, err := successAuth.Authenticate(newTestGinContext("good-token"))
	if err != nil || p == nil || p.Subject != "user-1" {
		t.Fatalf("expected successful authentication, got p=%v err=%v", p, err)
	}

	failAuth := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		ExtractorConfig: DefaultExtractorConfig(),
		BearerValidator: &fakeBearerValidator{err: errors.New("invalid token")},
		OnAuthenticate: func(_ context.Context, evt AuthEvent) {
			events = append(events, evt)
		},
	})

	_, err = failAuth.Authenticate(newTestGinContext("bad-token"))
	if err == nil {
		t.Fatalf("expected authentication failure")
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 reported AuthEvents, got %d: %+v", len(events), events)
	}
	if !events[0].Success || events[0].CredentialType != "bearer" {
		t.Fatalf("expected first event to report a successful bearer auth, got %+v", events[0])
	}
	if events[1].Success || events[1].CredentialType != "bearer" {
		t.Fatalf("expected second event to report a failed bearer auth, got %+v", events[1])
	}
	if events[0].Duration < 0 || events[1].Duration < 0 {
		t.Fatalf("expected non-negative durations, got %+v / %+v", events[0].Duration, events[1].Duration)
	}
}

// TestCompositeAuthenticator_NilOnAuthenticate_IsSafeNoOp confirms a nil
// hook (the default/zero value) never panics and never affects the
// returned result.
func TestCompositeAuthenticator_NilOnAuthenticate_IsSafeNoOp(t *testing.T) {
	auth := NewCompositeAuthenticator(CompositeAuthenticatorConfig{
		ExtractorConfig: DefaultExtractorConfig(),
		BearerValidator: &fakeBearerValidator{},
	})

	p, err := auth.Authenticate(newTestGinContext("good-token"))
	if err != nil || p == nil {
		t.Fatalf("expected successful authentication with a nil OnAuthenticate hook, got p=%v err=%v", p, err)
	}
}
