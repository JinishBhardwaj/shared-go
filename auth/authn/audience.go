package authn

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

// AudienceValidator is a callback for dynamic audience/client acceptance
// checks -- e.g. a runtime-onboarded M2M client list stored in a database,
// which can't be expressed as a static AllowedAudiences slice at
// validator-construction time because new entries are added after the
// validator is already built. Mirrors ASP.NET Core's
// TokenValidationParameters.AudienceValidator: audience acceptance is
// authn's decision (rejects as ErrInvalidAudience, i.e. a 401), never
// authz's (403) -- checking whether a client is currently ACTIVE/not-revoked,
// or any other business-state decision, does not belong in this hook; that
// is what authz.RequirementHandler is for.
//
// Deliberately receives the full parsed claims, not just an "aud" list:
// AWS Cognito's own client_credentials (M2M) access tokens carry no "aud"
// claim at all, only client_id -- the standard OIDC "audience" model
// doesn't fit every real IdP/grant-type combination. claims.GetAudience()
// works for callers with real "aud" claims; ExtractClientID(claims) covers
// Cognito-style client_id/azp/cid tokens instead.
//
// Called only after cryptographic verification (signature/issuer/expiry)
// has already succeeded, from ValidateToken's own goroutine -- it must not
// block indefinitely or panic (same contract as OnDecision/OnAuthenticate
// elsewhere in this module).
//
//   - Returning (true, nil) accepts the token.
//   - Returning (false, nil) is a deliberate, definitive rejection (this
//     audience/client is not accepted) -- fails closed, and never counts as
//     a breaker failure: this is the callback doing its job correctly, not
//     the callback failing.
//   - Returning a non-nil error signals a transient failure of the check
//     ITSELF (e.g. the backing database is unreachable), not a legitimate
//     answer. Always treated as "not accepted" (fail closed, same as every
//     other error path in this validator), but DOES count as a breaker
//     failure, so a sustained backend outage opens the breaker and stops
//     hammering the failing dependency instead of blocking every
//     subsequent token validation on it.
type AudienceValidator func(ctx context.Context, claims jwt.MapClaims) (bool, error)

// AudienceIntersects reports whether any of tokenAudiences appears in
// allowed. Shared by every TokenValidator implementation that enforces a
// static allow-list of audiences.
func AudienceIntersects(tokenAudiences, allowed []string) bool {
	for _, aud := range tokenAudiences {
		for _, a := range allowed {
			if aud == a {
				return true
			}
		}
	}
	return false
}
