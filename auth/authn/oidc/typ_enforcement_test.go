package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/authn"
	"github.com/golang-jwt/jwt/v5"
)

// validTokenWithKnownKidAndTyp is validTokenWithKnownKid (jwks_hardening_test.go)
// plus explicit control over the typ header, for exercising OIDCValidator's
// typ enforcement end-to-end against a real discovery+JWKS httptest server.
func (f *jwksFailureServer) validTokenWithKnownKidAndTyp(t *testing.T, hasTyp bool, typ string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": f.server.URL,
		"sub": "user-1",
		"aud": "any",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "kid-0"
	if hasTyp {
		token.Header["typ"] = typ
	} else {
		delete(token.Header, "typ")
	}
	s, err := token.SignedString(f.privateKey)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return s
}

// TestOIDCValidator_TypEnforcement_DefaultOff_AcceptsCognitoShapedToken is
// the OIDCValidator counterpart of JWTValidator's non-regression proof
// (authn/bearer): the default (TypEnforcementOff) must keep accepting a
// real, correctly-signed token with no typ header at all through the full
// discovery+JWKS+verify pipeline, not just the standalone EnforceTyp
// helper.
func TestOIDCValidator_TypEnforcement_DefaultOff_AcceptsCognitoShapedToken(t *testing.T) {
	f := newJWKSFailureServer(t)
	ctx := context.Background()

	v, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:         f.server.URL,
		SkipClientIDCheck: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tok := f.validTokenWithKnownKidAndTyp(t, false, "")
	if _, err := v.ValidateToken(ctx, tok); err != nil {
		t.Fatalf("default (TypEnforcementOff) must accept a Cognito-shaped token with no typ header, got: %v", err)
	}
}

// TestOIDCValidator_TypEnforcement_Strict_EndToEnd proves TypEnforcementStrict
// actually reaches OIDCValidator's real ValidateToken path (not just the
// standalone helper): a correctly-signed, otherwise entirely valid token
// missing the typ header is rejected, and one bearing "at+jwt" is accepted.
func TestOIDCValidator_TypEnforcement_Strict_EndToEnd(t *testing.T) {
	f := newJWKSFailureServer(t)
	ctx := context.Background()

	v, err := NewOIDCValidator(ctx, OIDCValidatorConfig{
		IssuerURL:         f.server.URL,
		SkipClientIDCheck: true,
		TypEnforcement:    authn.TypEnforcementStrict,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("missing typ rejected", func(t *testing.T) {
		tok := f.validTokenWithKnownKidAndTyp(t, false, "")
		if _, err := v.ValidateToken(ctx, tok); !errors.Is(err, authn.ErrUnexpectedTokenType) {
			t.Errorf("expected ErrUnexpectedTokenType, got: %v", err)
		}
	})

	t.Run("at+jwt accepted", func(t *testing.T) {
		tok := f.validTokenWithKnownKidAndTyp(t, true, "at+jwt")
		if _, err := v.ValidateToken(ctx, tok); err != nil {
			t.Errorf("expected success, got: %v", err)
		}
	})

	t.Run("wrong typ rejected", func(t *testing.T) {
		tok := f.validTokenWithKnownKidAndTyp(t, true, "id+jwt")
		if _, err := v.ValidateToken(ctx, tok); !errors.Is(err, authn.ErrUnexpectedTokenType) {
			t.Errorf("expected ErrUnexpectedTokenType, got: %v", err)
		}
	})
}
