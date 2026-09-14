package authn

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
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
	// Mutually exclusive with AllowedAudiences in practice: if both are set,
	// ExpectedClientID is enforced by the underlying go-oidc verifier and
	// AllowedAudiences is ignored.
	ExpectedClientID string

	// AllowedAudiences lists acceptable audiences ('aud' values) when more
	// than one app client must be accepted (e.g. a Cognito user pool shared
	// by several app clients). A token is accepted if its audience
	// intersects this list. Ignored if ExpectedClientID is set.
	AllowedAudiences []string

	// SkipClientIDCheck disables client_id/aud enforcement entirely. This
	// must be set explicitly and deliberately (Tier 0 #4: it used to be
	// hardcoded to true for every Cognito consumer via WithCognito,
	// silently disabling audience validation). If ExpectedClientID and
	// AllowedAudiences are both empty and this is left false, the validator
	// still has to skip the check (go-oidc requires SkipClientIDCheck when
	// ClientID is empty) -- but that path logs a loud server-side warning
	// so an unconfigured audience is never silent.
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
	provider         *oidc.Provider
	verifier         *oidc.IDTokenVerifier
	normalizer       ClaimsNormalizer
	allowedAudiences []string
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

	// Tier 0 #4: audience enforcement must be explicit. A single
	// ExpectedClientID is enforced by go-oidc itself (SkipClientIDCheck
	// stays false). Multiple AllowedAudiences can't be expressed in
	// go-oidc's single-ClientID config, so that check is deferred to
	// ValidateToken below and go-oidc's own check is skipped for this case
	// only. If neither is configured, the caller gets a loud server-side
	// warning instead of a silently-disabled check.
	multiAudience := cfg.ExpectedClientID == "" && len(cfg.AllowedAudiences) > 0
	skipClientIDCheck := cfg.SkipClientIDCheck || multiAudience
	if cfg.ExpectedClientID == "" && len(cfg.AllowedAudiences) == 0 && !cfg.SkipClientIDCheck {
		log.Printf("authn: OIDCValidator for issuer %q configured with no ExpectedClientID and no "+
			"AllowedAudiences -- audience validation is DISABLED. Set one of them, or pass "+
			"SkipClientIDCheck explicitly if this is deliberate.", cfg.IssuerURL)
		skipClientIDCheck = true
	}

	oidcConfig := &oidc.Config{
		ClientID:             cfg.ExpectedClientID,
		SupportedSigningAlgs: algs,
		SkipClientIDCheck:    skipClientIDCheck,
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

	var allowedAudiences []string
	if multiAudience {
		allowedAudiences = cfg.AllowedAudiences
	}

	return &OIDCValidator{
		provider:         provider,
		verifier:         verifier,
		normalizer:       norm,
		allowedAudiences: allowedAudiences,
	}, nil
}

// ValidateToken cryptographically verifies the token via dynamic JWKS and normalizes the claims.
func (v *OIDCValidator) ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error) {
	idToken, err := v.verifier.Verify(ctx, tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Tier 0 #4: when configured with multiple AllowedAudiences, go-oidc's
	// own single-ClientID check was deliberately skipped in
	// NewOIDCValidator above -- enforce it here instead, requiring the
	// token's audience to intersect the allowed set. This must never be
	// treated as optional: an empty allowedAudiences here means "no
	// restriction was configured" (see NewOIDCValidator's warning log for
	// that case), not "skip silently."
	if len(v.allowedAudiences) > 0 && !audienceIntersects(idToken.Audience, v.allowedAudiences) {
		return nil, fmt.Errorf("%w: token audience %v not in allowed set %v", ErrInvalidAudience, idToken.Audience, v.allowedAudiences)
	}

	var rawClaims map[string]any
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("%w: failed unmarshaling claims: %v", ErrInvalidToken, err)
	}

	claims := jwt.MapClaims(rawClaims)
	return v.normalizer.Normalize(claims, tokenStr)
}

// audienceIntersects reports whether any of tokenAudiences appears in allowed.
func audienceIntersects(tokenAudiences, allowed []string) bool {
	for _, aud := range tokenAudiences {
		for _, a := range allowed {
			if aud == a {
				return true
			}
		}
	}
	return false
}

// Provider returns the underlying coreos/go-oidc Provider (if initialized via discovery).
func (v *OIDCValidator) Provider() *oidc.Provider {
	return v.provider
}
