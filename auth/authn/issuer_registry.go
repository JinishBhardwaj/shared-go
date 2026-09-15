package authn

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

// ErrUnknownIssuer is returned by IssuerRegistry.ValidateToken when tokenStr's
// "iss" claim is missing, unparseable, or does not match any registered
// validator. There is deliberately no default/fallback validator: an
// unrecognized issuer always fails closed rather than being handed to
// whichever validator happens to be registered first (gap-analysis-final.md
// Tier 4 line 130: "Registry keyed by iss for multi-IdP/multi-tenant").
var ErrUnknownIssuer = errors.New("authn: no validator registered for token issuer")

// IssuerRegistry dispatches ValidateToken calls to one of several
// TokenValidators based on the incoming token's "iss" claim, so a single
// authn pipeline can accept tokens from more than one identity
// provider/tenant (e.g. two different Cognito user pools, or Cognito plus
// an external OIDC IdP) without the caller having to pre-classify which
// issuer a given request belongs to.
//
// IssuerRegistry itself implements TokenValidator (ValidateToken(ctx,
// tokenStr) (*principal.Principal, error)), so it is a drop-in
// BearerTokenValidator for authn/gin's CompositeAuthenticator/
// AuthenticationBuilder, exactly like CachingValidator (token_cache.go) --
// same duck-typed shape, deliberately not importing gin.
//
// Security note, load-bearing: the "iss" claim used to SELECT a validator is
// read from the token WITHOUT verifying its signature (same pre-verify-peek
// pattern as kid_gate.go's extractUnverifiedKid) -- it is only ever used to
// pick which validator's Verify to call, never treated as an authenticated
// fact on its own. The selected validator still performs its own full,
// independent verification (signature, issuer, audience, expiry, etc.)
// against its own configured issuer/key set. A token whose (unverified)
// "iss" claim happens to name a registered issuer, but whose signature does
// not match that issuer's keys, is rejected by that validator's own Verify
// call exactly as it would be today with a single validator -- the registry
// adds a selection step, not a trust decision. An unrecognized, missing, or
// malformed "iss" fails closed (ErrUnknownIssuer) with no fallback to any
// registered validator.
type IssuerRegistry struct {
	mu         sync.RWMutex
	validators map[string]TokenValidator
}

// NewIssuerRegistry creates an empty IssuerRegistry. Register at least one
// issuer before use; ValidateToken on an empty registry always returns
// ErrUnknownIssuer.
func NewIssuerRegistry() *IssuerRegistry {
	return &IssuerRegistry{validators: make(map[string]TokenValidator)}
}

// Register adds validator as the TokenValidator for issuer, replacing any
// previously registered validator for the same issuer. Panics if issuer is
// empty or validator is nil -- both are caller configuration errors that
// must fail at wire time, not silently produce a registry entry that can
// never match or that dispatches to a nil validator at request time (Tier 1
// line 100: "fail at wire time, not request time"). Returns the registry for
// chaining.
func (r *IssuerRegistry) Register(issuer string, validator TokenValidator) *IssuerRegistry {
	if issuer == "" {
		panic("authn: IssuerRegistry.Register: issuer must not be empty")
	}
	if validator == nil {
		panic("authn: IssuerRegistry.Register: validator must not be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.validators[issuer] = validator
	return r
}

// ValidateToken selects a registered TokenValidator by tokenStr's
// (unverified) "iss" claim and delegates full verification to it. Fails
// closed with ErrUnknownIssuer -- never falling back to any other registered
// validator -- if the claim is missing, unparseable, or not registered. See
// the type doc comment for why peeking at "iss" before verification is safe.
func (r *IssuerRegistry) ValidateToken(ctx context.Context, tokenStr string) (*principal.Principal, error) {
	iss, ok := extractUnverifiedIssuer(tokenStr)
	if !ok {
		return nil, fmt.Errorf("%w: no issuer claim present", ErrUnknownIssuer)
	}

	r.mu.RLock()
	validator, found := r.validators[iss]
	r.mu.RUnlock()
	if !found {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIssuer, iss)
	}

	return validator.ValidateToken(ctx, tokenStr)
}

// extractUnverifiedIssuer reads the "iss" claim from tokenStr WITHOUT
// verifying its signature -- used only to select which registered validator
// should perform the real (authoritative) verification. A missing,
// non-string, empty, or unparseable "iss", or a token too malformed to parse
// at all, is reported as ok=false; this function never treats a parse
// failure or the claim's presence as authoritative about the token's
// validity -- only the selected validator's own Verify call decides that.
func extractUnverifiedIssuer(tokenStr string) (iss string, ok bool) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil || token == nil {
		return "", false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", false
	}
	value, err := claims.GetIssuer()
	if err != nil || value == "" {
		return "", false
	}
	return value, true
}
