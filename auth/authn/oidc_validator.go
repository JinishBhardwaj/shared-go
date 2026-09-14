package authn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sony/gobreaker/v2"
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

	// DiscoveryTimeout bounds the OIDC discovery call
	// (.well-known/openid-configuration) with a context deadline, in
	// addition to whatever deadline the caller's own ctx already carries.
	// Defaults to 5s. Deliberately NOT the gap analysis's ~50ms figure --
	// that figure is stated for repo/Redis calls; a one-time HTTPS
	// discovery round trip realistically needs more than 50ms, and using
	// that value here would make every cold start spuriously trip the
	// discovery breaker.
	DiscoveryTimeout time.Duration

	// VerifyTimeout bounds each ValidateToken call's underlying
	// verifier.Verify (which may perform a JWKS fetch on an unknown kid)
	// with a context deadline. Defaults to 2s -- same reasoning as
	// DiscoveryTimeout: a real network round trip needs more than 50ms,
	// and an unrealistically tight deadline here would fail legitimate
	// requests under ordinary latency, which is itself a fail-open-shaped
	// risk in the opposite direction (denying valid users, or -- worse --
	// being loosened carelessly later to compensate).
	VerifyTimeout time.Duration
}

// OIDCValidator uses github.com/coreos/go-oidc/v3 to perform dynamic OIDC discovery,
// automatic JWKS caching, and background key rotation.
type OIDCValidator struct {
	provider         *oidc.Provider
	verifier         *oidc.IDTokenVerifier
	normalizer       ClaimsNormalizer
	allowedAudiences []string

	// verifyBreaker and verifyTimeout guard ValidateToken's JWKS-fetching
	// verifier.Verify call (Tier 3 "deadlines + breakers" for JWKS fetch).
	// Not exposed as a public field -- only the time.Duration knob
	// (OIDCValidatorConfig.VerifyTimeout) is public, same "don't leak the
	// breaker library into the public API" reasoning used elsewhere in
	// this gate.
	verifyBreaker *gobreaker.CircuitBreaker[*oidc.IDToken]
	verifyTimeout time.Duration
}

// discoveryBreakers is a package-level registry of one
// *gobreaker.CircuitBreaker[*oidc.Provider] per unique issuer/key-set URL,
// so that repeated NewOIDCValidator construction attempts against the same
// unreachable IdP (e.g. an app retrying its own boot in a loop) fail fast
// instead of hammering .well-known/openid-configuration on every attempt.
// A single OIDCValidator's own construction is a one-time event, so the
// breaker's value only shows up across repeated construction attempts --
// which is exactly the scenario "breaker on OIDC discovery" is meant to
// protect.
var (
	discoveryBreakersMu sync.Mutex
	discoveryBreakers   = map[string]*gobreaker.CircuitBreaker[*oidc.Provider]{}
)

func discoveryBreakerFor(key string) *gobreaker.CircuitBreaker[*oidc.Provider] {
	discoveryBreakersMu.Lock()
	defer discoveryBreakersMu.Unlock()

	if b, ok := discoveryBreakers[key]; ok {
		return b
	}
	b := gobreaker.NewCircuitBreaker[*oidc.Provider](gobreaker.Settings{Name: "authn-oidc-discovery:" + key})
	discoveryBreakers[key] = b
	return b
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

	discoveryTimeout := cfg.DiscoveryTimeout
	if discoveryTimeout <= 0 {
		discoveryTimeout = 5 * time.Second
	}
	verifyTimeout := cfg.VerifyTimeout
	if verifyTimeout <= 0 {
		verifyTimeout = 2 * time.Second
	}

	var verifier *oidc.IDTokenVerifier
	var provider *oidc.Provider

	if cfg.CustomKeySetURL != "" {
		// Directly use remote JWKS key-set without full OIDC discovery.
		// oidc.NewRemoteKeySet does no network I/O itself (it lazily
		// fetches on first Verify), so there is no discovery call here to
		// wrap with a breaker/deadline -- that cost is paid inside
		// ValidateToken's verifyBreaker/verifyTimeout instead.
		keySet := oidc.NewRemoteKeySet(ctx, cfg.CustomKeySetURL)
		verifier = oidc.NewVerifier(cfg.IssuerURL, keySet, oidcConfig)
	} else {
		// Full dynamic OIDC discovery via .well-known/openid-configuration.
		// Tier 3 "breaker on OIDC discovery": bounded by DiscoveryTimeout
		// and guarded by a per-issuer breaker so repeated construction
		// attempts against a down IdP fail fast instead of hammering
		// .well-known on every attempt.
		breaker := discoveryBreakerFor(cfg.IssuerURL)
		p, err := breaker.Execute(func() (*oidc.Provider, error) {
			dctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
			defer cancel()
			return oidc.NewProvider(dctx, cfg.IssuerURL)
		})
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
		verifyBreaker:    gobreaker.NewCircuitBreaker[*oidc.IDToken](gobreaker.Settings{Name: "authn-oidc-verify:" + cfg.IssuerURL}),
		verifyTimeout:    verifyTimeout,
	}, nil
}

// ValidateToken cryptographically verifies the token via dynamic JWKS and normalizes the claims.
//
// The underlying verifier.Verify call (which may perform a JWKS fetch on an
// unknown kid) is guarded by a per-validator circuit breaker and bounded by
// VerifyTimeout (Tier 3 "breaker on JWKS fetch"). A breaker-open or
// deadline-exceeded error surfaces identically to any other verification
// failure below -- wrapped in ErrInvalidToken -- so neither can ever be
// mistaken for, or silently degrade into, an accepted token.
func (v *OIDCValidator) ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error) {
	vctx, cancel := context.WithTimeout(ctx, v.verifyTimeout)
	defer cancel()

	idToken, err := v.verifyBreaker.Execute(func() (*oidc.IDToken, error) {
		return v.verifier.Verify(vctx, tokenStr)
	})
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
