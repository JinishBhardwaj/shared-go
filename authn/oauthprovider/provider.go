package oauthprovider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidClient        = errors.New("oauth: invalid client or secret")
	ErrInvalidGrant         = errors.New("oauth: invalid or expired grant")
	ErrPKCEVerificationFail = errors.New("oauth: pkce code verifier verification failed")
	ErrDeviceAuthPending    = errors.New("oauth: authorization_pending")
	ErrDeviceAuthExpired    = errors.New("oauth: device code has expired")
)

// DeviceAuthResponse is the RFC 8628 Device Authorization Response.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type authCodeRecord struct {
	Code                string
	ClientID            string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
	Scopes              []string
	ExpiresAt           time.Time
}

type deviceCodeRecord struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scopes     []string
	UserID     string
	Approved   bool
	ExpiresAt  time.Time
}

// MockOAuthProvider implements a complete RFC-compliant OAuth 2.0 / 2.1 token issuer
// supporting PKCE, Client Credentials, and Device Flow.
type MockOAuthProvider struct {
	mu           sync.RWMutex
	issuer       string
	audience     string
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	authCodes    map[string]*authCodeRecord
	deviceCodes  map[string]*deviceCodeRecord // deviceCode -> record
	userCodes    map[string]*deviceCodeRecord // userCode -> record
	clientSecret map[string]string            // clientID -> secret
}

// NewMockOAuthProvider initializes an RSA-backed OAuth mock provider.
func NewMockOAuthProvider(issuer, audience string) (*MockOAuthProvider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to generate RSA key: %w", err)
	}

	return &MockOAuthProvider{
		issuer:       issuer,
		audience:     audience,
		privateKey:   key,
		publicKey:    &key.PublicKey,
		authCodes:    make(map[string]*authCodeRecord),
		deviceCodes:  make(map[string]*deviceCodeRecord),
		userCodes:    make(map[string]*deviceCodeRecord),
		clientSecret: map[string]string{"service-worker-client": "secret-worker-password-123"},
	}, nil
}

// RegisterClient registers client credentials for M2M flow.
func (p *MockOAuthProvider) RegisterClient(clientID, secret string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clientSecret[clientID] = secret
}

// KeyFunc returns a jwt.Keyfunc for validating tokens signed by this provider.
func (p *MockOAuthProvider) KeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.publicKey, nil
	}
}

// PublicKey returns the RSA public key.
func (p *MockOAuthProvider) PublicKey() *rsa.PublicKey {
	return p.publicKey
}

// --- 1. Authorization Code Flow with PKCE ---

// GeneratePKCEVerifierAndChallenge generates a PKCE code verifier and S256 code challenge.
func GeneratePKCEVerifierAndChallenge() (verifier string, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// AuthorizePKCE simulates user login and authorization, returning an authorization code.
func (p *MockOAuthProvider) AuthorizePKCE(clientID, userID, challenge, method string, scopes []string) (string, error) {
	if method != "S256" {
		return "", errors.New("only S256 code_challenge_method is supported")
	}

	codeBytes := make([]byte, 24)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", err
	}
	code := hex.EncodeToString(codeBytes)

	rec := &authCodeRecord{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		Scopes:              scopes,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	p.mu.Lock()
	p.authCodes[code] = rec
	p.mu.Unlock()

	return code, nil
}

// ExchangeAuthCode exchanges an authorization code and PKCE verifier for an access token.
func (p *MockOAuthProvider) ExchangeAuthCode(clientID, code, codeVerifier string) (string, error) {
	p.mu.Lock()
	rec, exists := p.authCodes[code]
	if !exists {
		p.mu.Unlock()
		return "", ErrInvalidGrant
	}
	delete(p.authCodes, code) // Single-use code
	p.mu.Unlock()

	if time.Now().After(rec.ExpiresAt) {
		return "", ErrInvalidGrant
	}
	if rec.ClientID != clientID {
		return "", ErrInvalidGrant
	}

	// Verify PKCE: S256(verifier) == challenge
	h := sha256.Sum256([]byte(codeVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	if computedChallenge != rec.CodeChallenge {
		return "", ErrPKCEVerificationFail
	}

	claims := jwt.MapClaims{
		"iss":   p.issuer,
		"sub":   rec.UserID,
		"aud":   p.audience,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"gty":   "authorization_code",
		"amr":   []string{"pkce", "pwd"},
		"scope":     strings.Join(rec.Scopes, " "),
		"client_id": rec.ClientID,
	}

	return p.signToken(claims)
}

// --- 2. Client Credentials Grant (Machine to Machine) ---

// IssueClientCredentialsToken issues a token for service-to-service communication.
func (p *MockOAuthProvider) IssueClientCredentialsToken(clientID, clientSecret string, scopes []string) (string, error) {
	p.mu.RLock()
	secret, exists := p.clientSecret[clientID]
	p.mu.RUnlock()

	if !exists || secret != clientSecret {
		return "", ErrInvalidClient
	}

	claims := jwt.MapClaims{
		"iss":       p.issuer,
		"sub":       clientID, // In M2M, sub is typically the client_id or service principal
		"aud":       p.audience,
		"exp":       time.Now().Add(2 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"gty":       "client_credentials",
		"client_id": clientID,
		"scope":     strings.Join(scopes, " "),
	}

	return p.signToken(claims)
}

// --- 3. Device Authorization Grant (RFC 8628) ---

// RequestDeviceCode initiates the device authorization flow.
func (p *MockOAuthProvider) RequestDeviceCode(clientID string, scopes []string) (*DeviceAuthResponse, error) {
	dBytes := make([]byte, 20)
	if _, err := rand.Read(dBytes); err != nil {
		return nil, err
	}
	deviceCode := hex.EncodeToString(dBytes)

	// RFC 8628 recommends a user-friendly code, e.g. "WDJB-MJHT"
	uBytes := make([]byte, 4)
	if _, err := rand.Read(uBytes); err != nil {
		return nil, err
	}
	uHex := strings.ToUpper(hex.EncodeToString(uBytes))
	userCode := fmt.Sprintf("%s-%s", uHex[:4], uHex[4:])

	rec := &deviceCodeRecord{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		Approved:   false,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	p.mu.Lock()
	p.deviceCodes[deviceCode] = rec
	p.userCodes[userCode] = rec
	p.mu.Unlock()

	return &DeviceAuthResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         "https://example.com/activate",
		VerificationURIComplete: fmt.Sprintf("https://example.com/activate?user_code=%s", userCode),
		ExpiresIn:               600,
		Interval:                5,
	}, nil
}

// ApproveDeviceCode simulates the end-user entering the user_code on their browser/phone and authorizing the device.
func (p *MockOAuthProvider) ApproveDeviceCode(userCode, userID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	rec, exists := p.userCodes[userCode]
	if !exists {
		return errors.New("user code not found")
	}
	if time.Now().After(rec.ExpiresAt) {
		return ErrDeviceAuthExpired
	}

	rec.Approved = true
	rec.UserID = userID
	return nil
}

// PollDeviceToken is called by the device to exchange the device_code for an access token once approved.
func (p *MockOAuthProvider) PollDeviceToken(clientID, deviceCode string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	rec, exists := p.deviceCodes[deviceCode]
	if !exists {
		return "", ErrInvalidGrant
	}
	if time.Now().After(rec.ExpiresAt) {
		return "", ErrDeviceAuthExpired
	}
	if rec.ClientID != clientID {
		return "", ErrInvalidGrant
	}
	if !rec.Approved {
		return "", ErrDeviceAuthPending
	}

	// Clean up after successful grant
	delete(p.deviceCodes, rec.DeviceCode)
	delete(p.userCodes, rec.UserCode)

	claims := jwt.MapClaims{
		"iss":         p.issuer,
		"sub":         rec.UserID,
		"aud":         p.audience,
		"exp":         time.Now().Add(1 * time.Hour).Unix(),
		"iat":         time.Now().Unix(),
		"gty":         "urn:ietf:params:oauth:grant-type:device_code",
		"client_id":   rec.ClientID,
		"device_code": deviceCode,
		"scope":       strings.Join(rec.Scopes, " "),
	}

	return p.signToken(claims)
}

func (p *MockOAuthProvider) signToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(p.privateKey)
}
