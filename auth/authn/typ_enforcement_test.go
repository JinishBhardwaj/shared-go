package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signTestJWTWithTyp signs a token plus explicit control over the JOSE
// header "typ" value. hasTyp=false deletes the "typ" header entirely after
// jwt-go's own default ("JWT") is set by NewWithClaims -- this is what an
// AWS Cognito access token's header actually looks like (only "kid"/"alg",
// no "typ" at all), the shape every existing Cognito-flavored test fixture
// in this module uses.
func signTestJWTWithTyp(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims, hasTyp bool, typ string) string {
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating test RSA key: %v", err)
	}
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
			if err := EnforceTyp(TypEnforcementOff, tok); err != nil {
				t.Errorf("TypEnforcementOff must never reject, got: %v", err)
			}
		})
	}
}

func TestEnforceTyp_IfPresent(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating test RSA key: %v", err)
	}
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
			err := EnforceTyp(TypEnforcementIfPresent, tok)
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
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating test RSA key: %v", err)
	}
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
			err := EnforceTyp(TypEnforcementStrict, tok)
			if tc.wantErr && !errors.Is(err, ErrUnexpectedTokenType) {
				t.Errorf("expected ErrUnexpectedTokenType, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
