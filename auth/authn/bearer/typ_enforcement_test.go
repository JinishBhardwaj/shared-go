package bearer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/golang-jwt/jwt/v5"
)

// signTestJWTWithTyp is signTestJWT (validator_test.go) plus explicit
// control over the JOSE header "typ" value. hasTyp=false deletes the
// "typ" header entirely after jwt-go's own default ("JWT") is set by
// NewWithClaims -- this is what an AWS Cognito access token's header
// actually looks like (only "kid"/"alg", no "typ" at all).
func signTestJWTWithTyp(t *testing.T, key any, claims jwt.MapClaims, hasTyp bool, typ string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if hasTyp {
		token.Header["typ"] = typ
	} else {
		delete(token.Header, "typ")
	}
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed signing test token: %v", err)
	}
	return s
}

// TestJWTValidator_TypEnforcement_DefaultOff_AcceptsCognitoShapedToken is the
// critical non-regression proof: JWTValidatorConfig's zero-value
// TypEnforcement (i.e. every existing caller who never sets the field) must
// keep accepting a token with no typ header at all -- exactly the shape
// AWS Cognito issues today. If this test ever fails, this feature has been
// wired to default to something other than off, which would break every
// existing Cognito consumer of this library.
func TestJWTValidator_TypEnforcement_DefaultOff_AcceptsCognitoShapedToken(t *testing.T) {
	privKey, pubKey := generateTestRSAKey(t)
	v, err := NewJWTValidator(JWTValidatorConfig{
		KeyFunc: func(*jwt.Token) (any, error) { return pubKey, nil },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tok := signTestJWTWithTyp(t, privKey, jwt.MapClaims{
		"sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, false, "")

	if _, err := v.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("default (TypEnforcementOff) must accept a Cognito-shaped token with no typ header, got: %v", err)
	}
}

func TestJWTValidator_TypEnforcement_IfPresent_RejectsWrongTyp(t *testing.T) {
	privKey, pubKey := generateTestRSAKey(t)
	v, err := NewJWTValidator(JWTValidatorConfig{
		KeyFunc:        func(*jwt.Token) (any, error) { return pubKey, nil },
		TypEnforcement: authn.TypEnforcementIfPresent,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims := jwt.MapClaims{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()}

	t.Run("no typ header still passes", func(t *testing.T) {
		tok := signTestJWTWithTyp(t, privKey, claims, false, "")
		if _, err := v.ValidateToken(context.Background(), tok); err != nil {
			t.Errorf("expected success, got: %v", err)
		}
	})

	t.Run("ID-token-shaped typ is rejected", func(t *testing.T) {
		tok := signTestJWTWithTyp(t, privKey, claims, true, "JWT")
		_, err := v.ValidateToken(context.Background(), tok)
		if !errors.Is(err, authn.ErrUnexpectedTokenType) {
			t.Errorf("expected ErrUnexpectedTokenType, got: %v", err)
		}
	})

	t.Run("at+jwt passes", func(t *testing.T) {
		tok := signTestJWTWithTyp(t, privKey, claims, true, "at+jwt")
		if _, err := v.ValidateToken(context.Background(), tok); err != nil {
			t.Errorf("expected success, got: %v", err)
		}
	})
}
