package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateTestRSAKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating test RSA key: %v", err)
	}
	return key, &key.PublicKey
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed signing test token: %v", err)
	}
	return s
}

func TestJWTValidator_Flows(t *testing.T) {
	privKey, pubKey := generateTestRSAKey(t)
	issuer := "https://auth.example.com"
	audience := "https://api.example.com"

	validator, err := NewJWTValidator(JWTValidatorConfig{
		KeyFunc: func(token *jwt.Token) (any, error) {
			return pubKey, nil
		},
		ExpectedIssuer:     issuer,
		ExpectedAudience:   audience,
		ClockSkewTolerance: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error creating validator: %v", err)
	}

	tests := []struct {
		name           string
		claims         jwt.MapClaims
		expectedMethod AuthMethod
		expectedSub    string
		expectedScopes []string
	}{
		{
			name: "AuthCode + PKCE Token",
			claims: jwt.MapClaims{
				"iss":       issuer,
				"aud":       audience,
				"sub":       "user_pkce_123",
				"exp":       time.Now().Add(time.Hour).Unix(),
				"iat":       time.Now().Unix(),
				"gty":       "authorization_code",
				"amr":       []any{"pkce"},
				"client_id": "spa-client-1",
				"scope":     "read:profile write:profile",
			},
			expectedMethod: AuthMethodAuthCodePKCE,
			expectedSub:    "user_pkce_123",
			expectedScopes: []string{"read:profile", "write:profile"},
		},
		{
			name: "Client Credentials M2M Token",
			claims: jwt.MapClaims{
				"iss":       issuer,
				"aud":       audience,
				"sub":       "backend-worker-client",
				"exp":       time.Now().Add(time.Hour).Unix(),
				"iat":       time.Now().Unix(),
				"gty":       "client_credentials",
				"client_id": "backend-worker-client",
				"scope":     "sync:data reports:export",
			},
			expectedMethod: AuthMethodClientCredentials,
			expectedSub:    "backend-worker-client",
			expectedScopes: []string{"sync:data", "reports:export"},
		},
		{
			name: "Device Flow Token",
			claims: jwt.MapClaims{
				"iss":         issuer,
				"aud":         audience,
				"sub":         "user_device_999",
				"exp":         time.Now().Add(time.Hour).Unix(),
				"iat":         time.Now().Unix(),
				"gty":         "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "cli-device-tool",
				"device_code": "dev-code-xyz",
				"scope":       "offline_access read:data",
			},
			expectedMethod: AuthMethodDeviceFlow,
			expectedSub:    "user_device_999",
			expectedScopes: []string{"offline_access", "read:data"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rawToken := signTestJWT(t, privKey, tc.claims)
			id, err := validator.ValidateToken(context.Background(), rawToken)
			if err != nil {
				t.Fatalf("ValidateToken failed: %v", err)
			}

			if id.Method != tc.expectedMethod {
				t.Errorf("expected method %s, got %s", tc.expectedMethod, id.Method)
			}
			if id.Subject != tc.expectedSub {
				t.Errorf("expected subject %s, got %s", tc.expectedSub, id.Subject)
			}
			if !id.HasAllScopes(tc.expectedScopes...) {
				t.Errorf("expected scopes %v, got %v", tc.expectedScopes, id.Scopes)
			}
		})
	}
}

func TestJWTValidator_ValidationErrors(t *testing.T) {
	privKey, pubKey := generateTestRSAKey(t)
	otherKey, _ := generateTestRSAKey(t)
	issuer := "https://auth.example.com"
	audience := "https://api.example.com"

	validator, _ := NewJWTValidator(JWTValidatorConfig{
		KeyFunc: func(token *jwt.Token) (any, error) {
			return pubKey, nil
		},
		ExpectedIssuer:     issuer,
		ExpectedAudience:   audience,
		ClockSkewTolerance: 1 * time.Second,
	})

	t.Run("Expired Token", func(t *testing.T) {
		token := signTestJWT(t, privKey, jwt.MapClaims{
			"iss": issuer,
			"aud": audience,
			"sub": "user1",
			"exp": time.Now().Add(-5 * time.Minute).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err == nil || err != ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired, got %v", err)
		}
	})

	t.Run("Invalid Signature", func(t *testing.T) {
		// Signed by different key
		token := signTestJWT(t, otherKey, jwt.MapClaims{
			"iss": issuer,
			"aud": audience,
			"sub": "user1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err == nil {
			t.Error("expected error for invalid signature, got nil")
		}
	})

	t.Run("Invalid Issuer", func(t *testing.T) {
		token := signTestJWT(t, privKey, jwt.MapClaims{
			"iss": "https://attacker.example.com",
			"aud": audience,
			"sub": "user1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err == nil || err != ErrInvalidIssuer {
			t.Errorf("expected ErrInvalidIssuer, got %v", err)
		}
	})

	t.Run("Invalid Audience", func(t *testing.T) {
		token := signTestJWT(t, privKey, jwt.MapClaims{
			"iss": issuer,
			"aud": "https://other-service.example.com",
			"sub": "user1",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		_, err := validator.ValidateToken(context.Background(), token)
		if err == nil || err != ErrInvalidAudience {
			t.Errorf("expected ErrInvalidAudience, got %v", err)
		}
	})
}
