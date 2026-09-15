package authn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

// signedTokenWithIssuer builds a syntactically valid, HMAC-signed JWT
// carrying iss as its "iss" claim. The signature/secret is irrelevant to
// every test in this file: IssuerRegistry only ever peeks at the
// unverified "iss" claim to pick a validator, never verifies the
// signature itself -- that is deliberately left to the (fake, in these
// tests) inner validator, exactly as it would be to a real JWTValidator/
// OIDCValidator in production.
func signedTokenWithIssuer(t *testing.T, iss string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	if iss != "" {
		claims["iss"] = iss
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte("test-secret-irrelevant-to-registry-dispatch"))
	if err != nil {
		t.Fatalf("failed signing test token: %v", err)
	}
	return s
}

func TestIssuerRegistry_DispatchesByIssuer_ToCorrectValidator(t *testing.T) {
	validatorA := &countingValidator{result: func(string) (*principal.Principal, error) {
		return &principal.Principal{Subject: "user-a"}, nil
	}}
	validatorB := &countingValidator{result: func(string) (*principal.Principal, error) {
		return &principal.Principal{Subject: "user-b"}, nil
	}}

	reg := NewIssuerRegistry().
		Register("https://issuer-a.example", validatorA).
		Register("https://issuer-b.example", validatorB)

	ctx := context.Background()

	pA, err := reg.ValidateToken(ctx, signedTokenWithIssuer(t, "https://issuer-a.example"))
	if err != nil || pA == nil || pA.Subject != "user-a" {
		t.Fatalf("issuer-a token: got principal=%+v err=%v, want user-a/nil", pA, err)
	}
	pB, err := reg.ValidateToken(ctx, signedTokenWithIssuer(t, "https://issuer-b.example"))
	if err != nil || pB == nil || pB.Subject != "user-b" {
		t.Fatalf("issuer-b token: got principal=%+v err=%v, want user-b/nil", pB, err)
	}

	if got := validatorA.callCount(); got != 1 {
		t.Errorf("validatorA: expected exactly 1 call (only the issuer-a token), got %d", got)
	}
	if got := validatorB.callCount(); got != 1 {
		t.Errorf("validatorB: expected exactly 1 call (only the issuer-b token), got %d", got)
	}
}

// TestIssuerRegistry_UnknownIssuer_FailsClosed_NoFallback is the load-bearing
// fail-closed proof for this task: a token whose iss claim names an issuer
// that was never registered must be rejected outright, and -- critically --
// must NEVER be handed to some other registered validator as a fallback
// (which would let an attacker who can put an arbitrary string in an
// unverified "iss" claim probe or pass it to a validator whose keys/issuer
// config were never meant to see it).
func TestIssuerRegistry_UnknownIssuer_FailsClosed_NoFallback(t *testing.T) {
	validatorA := &countingValidator{result: func(string) (*principal.Principal, error) {
		return &principal.Principal{Subject: "user-a"}, nil
	}}
	reg := NewIssuerRegistry().Register("https://issuer-a.example", validatorA)

	p, err := reg.ValidateToken(context.Background(), signedTokenWithIssuer(t, "https://attacker-controlled.example"))
	if p != nil {
		t.Fatalf("unknown issuer: expected nil principal, got %+v", p)
	}
	if !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("unknown issuer: expected ErrUnknownIssuer, got %v", err)
	}
	if got := validatorA.callCount(); got != 0 {
		t.Fatalf("unknown issuer: registered validator must never be consulted as a fallback, but was called %d time(s)", got)
	}
}

func TestIssuerRegistry_MissingIssuerClaim_FailsClosed(t *testing.T) {
	validatorA := &countingValidator{result: func(string) (*principal.Principal, error) {
		return &principal.Principal{Subject: "user-a"}, nil
	}}
	reg := NewIssuerRegistry().Register("https://issuer-a.example", validatorA)

	p, err := reg.ValidateToken(context.Background(), signedTokenWithIssuer(t, ""))
	if p != nil {
		t.Fatalf("missing iss: expected nil principal, got %+v", p)
	}
	if !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("missing iss: expected ErrUnknownIssuer, got %v", err)
	}
	if got := validatorA.callCount(); got != 0 {
		t.Fatalf("missing iss: registered validator must never be consulted, but was called %d time(s)", got)
	}
}

func TestIssuerRegistry_MalformedToken_FailsClosed(t *testing.T) {
	validatorA := &countingValidator{result: func(string) (*principal.Principal, error) {
		return &principal.Principal{Subject: "user-a"}, nil
	}}
	reg := NewIssuerRegistry().Register("https://issuer-a.example", validatorA)

	p, err := reg.ValidateToken(context.Background(), "not-even-remotely-a-jwt")
	if p != nil {
		t.Fatalf("malformed token: expected nil principal, got %+v", p)
	}
	if !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("malformed token: expected ErrUnknownIssuer, got %v", err)
	}
	if got := validatorA.callCount(); got != 0 {
		t.Fatalf("malformed token: registered validator must never be consulted, but was called %d time(s)", got)
	}
}

func TestIssuerRegistry_EmptyRegistry_FailsClosed(t *testing.T) {
	reg := NewIssuerRegistry()
	p, err := reg.ValidateToken(context.Background(), signedTokenWithIssuer(t, "https://issuer-a.example"))
	if p != nil {
		t.Fatalf("empty registry: expected nil principal, got %+v", p)
	}
	if !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("empty registry: expected ErrUnknownIssuer, got %v", err)
	}
}

// TestIssuerRegistry_SelectedValidatorFailure_PropagatesUnchanged proves the
// registry is a pure selection step, not a second trust decision: if the
// validator selected by the (unverified) iss claim itself rejects the token
// (e.g. because the real signature does not match that issuer's keys --
// exactly what happens if an attacker forges an "iss" claim naming a real,
// registered issuer but signs with the wrong/no key), that rejection must
// come back to the caller completely unchanged, never swallowed into a
// success and never silently retried against a different validator.
func TestIssuerRegistry_SelectedValidatorFailure_PropagatesUnchanged(t *testing.T) {
	sentinel := errors.New("signature verification failed")
	validatorA := &countingValidator{result: func(string) (*principal.Principal, error) {
		return nil, sentinel
	}}
	reg := NewIssuerRegistry().Register("https://issuer-a.example", validatorA)

	p, err := reg.ValidateToken(context.Background(), signedTokenWithIssuer(t, "https://issuer-a.example"))
	if p != nil {
		t.Fatalf("expected nil principal on inner validator failure, got %+v", p)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the inner validator's error to propagate unchanged, got %v", err)
	}
	if got := validatorA.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 call to the selected validator, got %d", got)
	}
}

func TestIssuerRegistry_Register_PanicsOnEmptyIssuer(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected a panic registering an empty issuer")
		}
		if !strings.Contains(r.(string), "issuer must not be empty") {
			t.Fatalf("unexpected panic message: %v", r)
		}
	}()
	NewIssuerRegistry().Register("", &countingValidator{})
}

func TestIssuerRegistry_Register_PanicsOnNilValidator(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected a panic registering a nil validator")
		}
		if !strings.Contains(r.(string), "validator must not be nil") {
			t.Fatalf("unexpected panic message: %v", r)
		}
	}()
	NewIssuerRegistry().Register("https://issuer-a.example", nil)
}

func TestIssuerRegistry_Register_ReplacesPriorValidatorForSameIssuer(t *testing.T) {
	first := &countingValidator{result: func(string) (*principal.Principal, error) {
		return &principal.Principal{Subject: "old"}, nil
	}}
	second := &countingValidator{result: func(string) (*principal.Principal, error) {
		return &principal.Principal{Subject: "new"}, nil
	}}
	reg := NewIssuerRegistry()
	reg.Register("https://issuer-a.example", first)
	reg.Register("https://issuer-a.example", second)

	p, err := reg.ValidateToken(context.Background(), signedTokenWithIssuer(t, "https://issuer-a.example"))
	if err != nil || p == nil || p.Subject != "new" {
		t.Fatalf("expected the second registration to win, got %+v, err=%v", p, err)
	}
	if got := first.callCount(); got != 0 {
		t.Fatalf("expected the replaced validator to never be called, got %d calls", got)
	}
}

// TestIssuerRegistry_ConcurrentRegisterAndValidate exercises Register and
// ValidateToken concurrently under -race to confirm the registry's own
// locking is sufficient (no unprotected map access on either path).
func TestIssuerRegistry_ConcurrentRegisterAndValidate(t *testing.T) {
	reg := NewIssuerRegistry()
	v := &countingValidator{result: func(string) (*principal.Principal, error) {
		return &principal.Principal{Subject: "u"}, nil
	}}
	reg.Register("https://issuer-0.example", v)
	tok := signedTokenWithIssuer(t, "https://issuer-0.example")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = reg.ValidateToken(context.Background(), tok)
		}()
		go func() {
			defer wg.Done()
			reg.Register("https://issuer-extra.example", v)
		}()
	}
	wg.Wait()
}
