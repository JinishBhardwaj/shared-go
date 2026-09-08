package oauthprovider

import (
	"testing"
)

func TestMockOAuthProvider_PKCE(t *testing.T) {
	provider, err := NewMockOAuthProvider("https://auth.example.com", "https://api.example.com")
	if err != nil {
		t.Fatalf("failed creating provider: %v", err)
	}

	verifier, challenge, err := GeneratePKCEVerifierAndChallenge()
	if err != nil {
		t.Fatalf("failed generating pkce verifier and challenge: %v", err)
	}

	codeBad, err := provider.AuthorizePKCE("spa-client", "user-123", challenge, "S256", []string{"read:data"})
	if err != nil {
		t.Fatalf("failed AuthorizePKCE: %v", err)
	}

	// Bad verifier
	_, err = provider.ExchangeAuthCode("spa-client", codeBad, "wrong-verifier-12345678901234567890")
	if err != ErrPKCEVerificationFail {
		t.Errorf("expected ErrPKCEVerificationFail, got %v", err)
	}

	// Good exchange
	codeGood, err := provider.AuthorizePKCE("spa-client", "user-123", challenge, "S256", []string{"read:data"})
	if err != nil {
		t.Fatalf("failed AuthorizePKCE: %v", err)
	}

	token, err := provider.ExchangeAuthCode("spa-client", codeGood, verifier)
	if err != nil {
		t.Fatalf("failed ExchangeAuthCode: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}

	// Code reuse fails (single-use grant)
	_, err = provider.ExchangeAuthCode("spa-client", codeGood, verifier)
	if err != ErrInvalidGrant {
		t.Errorf("expected ErrInvalidGrant on reused code, got %v", err)
	}
}

func TestMockOAuthProvider_ClientCredentials(t *testing.T) {
	provider, err := NewMockOAuthProvider("https://auth.example.com", "https://api.example.com")
	if err != nil {
		t.Fatalf("failed creating provider: %v", err)
	}

	provider.RegisterClient("service-1", "secret-1")

	// Bad secret
	_, err = provider.IssueClientCredentialsToken("service-1", "wrong-secret", []string{"sync:data"})
	if err != ErrInvalidClient {
		t.Errorf("expected ErrInvalidClient, got %v", err)
	}

	// Good secret
	token, err := provider.IssueClientCredentialsToken("service-1", "secret-1", []string{"sync:data"})
	if err != nil {
		t.Fatalf("failed IssueClientCredentialsToken: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestMockOAuthProvider_DeviceFlow(t *testing.T) {
	provider, err := NewMockOAuthProvider("https://auth.example.com", "https://api.example.com")
	if err != nil {
		t.Fatalf("failed creating provider: %v", err)
	}

	resp, err := provider.RequestDeviceCode("cli-client", []string{"read:logs"})
	if err != nil {
		t.Fatalf("failed RequestDeviceCode: %v", err)
	}

	// Poll before approve -> pending
	_, err = provider.PollDeviceToken("cli-client", resp.DeviceCode)
	if err != ErrDeviceAuthPending {
		t.Errorf("expected ErrDeviceAuthPending, got %v", err)
	}

	// Approve
	if err := provider.ApproveDeviceCode(resp.UserCode, "cli-user-42"); err != nil {
		t.Fatalf("failed ApproveDeviceCode: %v", err)
	}

	// Poll after approve -> success
	token, err := provider.PollDeviceToken("cli-client", resp.DeviceCode)
	if err != nil {
		t.Fatalf("failed PollDeviceToken: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}

	// Poll again -> code already consumed
	_, err = provider.PollDeviceToken("cli-client", resp.DeviceCode)
	if err != ErrInvalidGrant {
		t.Errorf("expected ErrInvalidGrant, got %v", err)
	}
}
