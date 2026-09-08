package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrOIDCProviderInit = errors.New("authn: failed to initialize OIDC provider")
)

// OIDCValidatorConfig configures dynamic OIDC discovery and JWKS validation.
type OIDCValidatorConfig struct {
	// IssuerURL is the base URL of the Identity Provider (e.g. "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abcdef").
	// The validator will discover endpoints from IssuerURL + "/.well-known/openid-configuration".
	IssuerURL string

	// ExpectedClientID is the OAuth client identifier (e.g., Cognito App Client ID). Optional.
	ExpectedClientID string

	// SkipClientIDCheck disables client_id/aud enforcement at the OIDC verifier level.
	SkipClientIDCheck bool

	// SupportedSigningAlgs specifies permitted JWT signing algorithms (e.g. ["RS256"]).
	// Defaults to RS256 if empty.
	SupportedSigningAlgs []string

	// Normalizer maps raw claims into the unified Identity context.
	// Defaults to CognitoClaimsNormalizer if nil.
	Normalizer ClaimsNormalizer

	// CustomKeySetURL allows bypassing .well-known discovery and pointing directly to a JWKS URI. Optional.
	CustomKeySetURL string
}

// OIDCValidator uses github.com/coreos/go-oidc/v3 to perform dynamic OIDC discovery,
// automatic JWKS caching, and background key rotation.
type OIDCValidator struct {
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	normalizer ClaimsNormalizer
}

// NewOIDCValidator initializes an OIDC discovery validator using coreos/go-oidc/v3.
func NewOIDCValidator(ctx context.Context, cfg OIDCValidatorConfig) (*OIDCValidator, error) {
	if cfg.IssuerURL == "" && cfg.CustomKeySetURL == "" {
		return nil, errors.New("authn: either IssuerURL or CustomKeySetURL must be specified")
	}

	algs := cfg.SupportedSigningAlgs
	if len(algs) == 0 {
		algs = []string{oidc.RS256}
	}

	norm := cfg.Normalizer
	if norm == nil {
		norm = NewCognitoClaimsNormalizer()
	}

	oidcConfig := &oidc.Config{
		ClientID:             cfg.ExpectedClientID,
		SupportedSigningAlgs: algs,
		SkipClientIDCheck:    cfg.SkipClientIDCheck || cfg.ExpectedClientID == "",
	}

	var verifier *oidc.IDTokenVerifier
	var provider *oidc.Provider

	if cfg.CustomKeySetURL != "" {
		// Directly use remote JWKS key-set without full OIDC discovery
		keySet := oidc.NewRemoteKeySet(ctx, cfg.CustomKeySetURL)
		verifier = oidc.NewVerifier(cfg.IssuerURL, keySet, oidcConfig)
	} else {
		// Full dynamic OIDC discovery via .well-known/openid-configuration
		p, err := oidc.NewProvider(ctx, cfg.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrOIDCProviderInit, err)
		}
		provider = p
		verifier = p.Verifier(oidcConfig)
	}

	return &OIDCValidator{
		provider:   provider,
		verifier:   verifier,
		normalizer: norm,
	}, nil
}

// ValidateToken cryptographically verifies the token via dynamic JWKS and normalizes the claims.
func (v *OIDCValidator) ValidateToken(ctx context.Context, tokenStr string) (*Principal, error) {
	idToken, err := v.verifier.Verify(ctx, tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("%w: failed unmarshaling claims: %v", ErrInvalidToken, err)
	}

	claims := jwt.MapClaims(rawClaims)
	return v.normalizer.Normalize(claims, tokenStr)
}

// Provider returns the underlying coreos/go-oidc Provider (if initialized via discovery).
func (v *OIDCValidator) Provider() *oidc.Provider {
	return v.provider
}
