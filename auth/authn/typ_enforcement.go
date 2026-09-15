package authn

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// TypEnforcementMode controls whether a validator enforces RFC 9068 §2.1's
// convention that an OAuth 2.0 access token's JOSE header carries
// "typ": "at+jwt", to defend against a token-confusion attack in which a
// token minted for a different purpose (most commonly an OIDC ID token) is
// presented where an access token is expected and is accepted anyway
// because the two are otherwise structurally identical JWTs.
//
// RFC 9068 makes "typ: at+jwt" a SHOULD, not a MUST, and it is deliberately
// NOT set by every IdP today. In particular, AWS Cognito access tokens (as
// documented by AWS and observed in this codebase's own existing Cognito
// integration and test fixtures -- see authn/gin/builder_test.go and
// oidc_validator_test.go, none of which stamp a typ header on their
// Cognito-shaped test tokens) carry only "kid" and "alg" in their header,
// with no "typ" claim at all. A hard MUST-have-"at+jwt" requirement would
// therefore reject every existing Cognito consumer of this library
// outright. There is no live network call available to this package to
// re-confirm Cognito's current header shape at runtime -- this is a
// documented characteristic of the token format, not something dynamically
// discoverable per request -- so enforcement defaults to Off and must be
// opted into explicitly, in one of the two shapes below, never silently
// assumed strict.
type TypEnforcementMode int

const (
	// TypEnforcementOff performs no typ-header check at all. This is the
	// zero value and the default for both JWTValidatorConfig and
	// OIDCValidatorConfig, specifically so that adding this field never
	// changes behavior for an existing caller who does not set it --
	// including every existing Cognito consumer, whose tokens have no typ
	// header to check.
	TypEnforcementOff TypEnforcementMode = iota

	// TypEnforcementIfPresent rejects a token whose typ header IS present
	// but does not identify it as an access token (i.e. is not "at+jwt",
	// case-insensitively, optionally prefixed "application/" per RFC 7515
	// §4.1.9). A token with NO typ header at all is not rejected by this
	// mode -- absence is not itself a failure, since many IdPs (Cognito
	// among them) never set the header on any token, access or ID. This
	// mode is safe to enable against an IdP that sometimes sets typ
	// (e.g. distinguishing its own ID tokens with "typ: JWT" or similar)
	// without also requiring every access token carry "at+jwt".
	TypEnforcementIfPresent

	// TypEnforcementStrict requires the typ header be present AND equal
	// "at+jwt". Only enable this against an IdP confirmed (out of band, by
	// the operator configuring this validator -- this package cannot probe
	// that at runtime) to stamp "at+jwt" on every access token it issues.
	// Enabling this against AWS Cognito's default configuration will
	// reject every token, since Cognito does not set typ at all.
	TypEnforcementStrict
)

// ErrUnexpectedTokenType is returned by TypEnforcementIfPresent/
// TypEnforcementStrict when a token's JOSE header "typ" value does not
// identify it as an RFC 9068 access token.
var ErrUnexpectedTokenType = errors.New("authn: token typ header does not identify an access token (at+jwt)")

// atJWTTyp is the RFC 9068 §2.1 canonical "typ" header value for an OAuth
// 2.0 access token.
const atJWTTyp = "at+jwt"

// isATJWTTyp reports whether typ (a JOSE header "typ" value) identifies an
// RFC 9068 access token, applying RFC 7515 §4.1.9's rule that a "typ" value
// SHOULD be compared case-insensitively and with any "application/" prefix
// disregarded (so "at+jwt", "AT+JWT", and "application/at+jwt" are all
// equivalent).
func isATJWTTyp(typ string) bool {
	typ = strings.ToLower(strings.TrimSpace(typ))
	typ = strings.TrimPrefix(typ, "application/")
	return typ == atJWTTyp
}

// extractHeaderTyp reads the JOSE header "typ" value from tokenStr WITHOUT
// re-verifying its signature. Callers MUST only call this after tokenStr's
// signature has already been cryptographically verified by the real
// verifier (JWTValidator's jwt.ParseWithClaims / OIDCValidator's
// verifier.Verify) -- unlike kid_gate.go's extractUnverifiedKid and
// issuer_registry.go's extractUnverifiedIssuer, which peek a claim BEFORE
// verification purely to make a routing/rate-limit decision and never treat
// the peeked value as authoritative, the typ value read here IS trusted
// once read: in a JWS compact serialization, the JOSE header is part of the
// content covered by the signature, so if the signature already checked
// out, the header could not have been altered in transit. Re-parsing here
// (rather than threading the already-decoded header through from each
// validator's own parse call) costs one more cheap base64/JSON decode and
// keeps this check's implementation identical regardless of which
// validator calls it.
func extractHeaderTyp(tokenStr string) (typ string, present bool) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil || token == nil {
		return "", false
	}
	raw, ok := token.Header["typ"]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// enforceTyp applies mode to tokenStr's typ header, per TypEnforcementMode's
// own doc comments. Callers MUST only call this after tokenStr's signature
// has already been verified -- see extractHeaderTyp.
func enforceTyp(mode TypEnforcementMode, tokenStr string) error {
	if mode == TypEnforcementOff {
		return nil
	}
	typ, present := extractHeaderTyp(tokenStr)
	if !present {
		if mode == TypEnforcementStrict {
			return fmt.Errorf("%w: missing typ header", ErrUnexpectedTokenType)
		}
		return nil
	}
	if !isATJWTTyp(typ) {
		return fmt.Errorf("%w: got %q", ErrUnexpectedTokenType, typ)
	}
	return nil
}
