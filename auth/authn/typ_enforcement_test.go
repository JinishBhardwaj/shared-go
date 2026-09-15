package authn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signTestJWTWithTyp is signTestJWT (jwt_validator_test.go) plus explicit
// control over the JOSE header "typ" value. hasTyp=false deletes the
// "typ" header entirely after jwt-go's own default ("JWT") is set by
// NewWithClaims -- this is what an AWS Cognito access token's header
// actually looks like (only "kid"/"alg", no "typ" at all), and is the
// shape every existing Cognito-flavored test fixture in this package uses
// (none of them set typ), so this helper's hasTyp=false path is not a new
// invented shape, it is the pre-existing default.
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

func TestIsATJWTTyp(t *testing.T) {
	tests := []struct {
		typ  string
		want bool
	}{
		{"at+jwt", true},
		{"AT+JWT", true},
		{"At+Jwt", true},
		{"application/at+jwt", true},
		{"APPLICATION/AT+JWT", true},
		{"  at+jwt  ", true},
		{"JWT", false},
		{"id+jwt", false},
		{"", false},
		{"application/jwt", false},
	}
	for _, tc := range tests {
		if got := isATJWTTyp(tc.typ); got != tc.want {
			t.Errorf("isATJWTTyp(%q) = %v, want %v", tc.typ, got, tc.want)
		}
	}
}

func TestEnforceTyp_OffNeverRejects(t *testing.T) {
	key, _ := generateTestRSAKey(t)
	claims := jwt.MapClaims{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()}

	for _, tc := range []struct {
		name   string
		hasTyp bool
		typ    string
	}{
		{"no typ header at all (Cognito shape)", false, ""},
		{"typ=JWT", true, "JWT"},
		{"typ=id+jwt", true, "id+jwt"},
		{"typ=at+jwt", true, "at+jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := signTestJWTWithTyp(t, key, claims, tc.hasTyp, tc.typ)
			if err := enforceTyp(TypEnforcementOff, tok); err != nil {
				t.Errorf("TypEnforcementOff must never reject, got: %v", err)
			}
		})
	}
}

func TestEnforceTyp_IfPresent(t *testing.T) {
	key, _ := generateTestRSAKey(t)
	claims := jwt.MapClaims{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()}

	tests := []struct {
		name    string
		hasTyp  bool
		typ     string
		wantErr bool
	}{
		{"absent (Cognito shape) passes", false, "", false},
		{"at+jwt passes", true, "at+jwt", false},
		{"AT+JWT passes (case-insensitive)", true, "AT+JWT", false},
		{"application/at+jwt passes (prefix allowed)", true, "application/at+jwt", false},
		{"JWT rejected", true, "JWT", true},
		{"id+jwt rejected", true, "id+jwt", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := signTestJWTWithTyp(t, key, claims, tc.hasTyp, tc.typ)
			err := enforceTyp(TypEnforcementIfPresent, tok)
			if tc.wantErr && !errors.Is(err, ErrUnexpectedTokenType) {
				t.Errorf("expected ErrUnexpectedTokenType, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestEnforceTyp_Strict(t *testing.T) {
	key, _ := generateTestRSAKey(t)
	claims := jwt.MapClaims{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()}

	tests := []struct {
		name    string
		hasTyp  bool
		typ     string
		wantErr bool
	}{
		{"absent (Cognito shape) rejected in strict mode", false, "", true},
		{"at+jwt passes", true, "at+jwt", false},
		{"JWT rejected", true, "JWT", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := signTestJWTWithTyp(t, key, claims, tc.hasTyp, tc.typ)
			err := enforceTyp(TypEnforcementStrict, tok)
			if tc.wantErr && !errors.Is(err, ErrUnexpectedTokenType) {
				t.Errorf("expected ErrUnexpectedTokenType, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
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
		TypEnforcement: TypEnforcementIfPresent,
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
		if !errors.Is(err, ErrUnexpectedTokenType) {
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
// the OIDCValidator counterpart of the JWTValidator non-regression proof
// above: the default (TypEnforcementOff) must keep accepting a real,
// correctly-signed token with no typ header at all through the full
// discovery+JWKS+verify pipeline, not just the standalone enforceTyp
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
		TypEnforcement:    TypEnforcementStrict,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("missing typ rejected", func(t *testing.T) {
		tok := f.validTokenWithKnownKidAndTyp(t, false, "")
		if _, err := v.ValidateToken(ctx, tok); !errors.Is(err, ErrUnexpectedTokenType) {
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
		if _, err := v.ValidateToken(ctx, tok); !errors.Is(err, ErrUnexpectedTokenType) {
			t.Errorf("expected ErrUnexpectedTokenType, got: %v", err)
		}
	})
}
