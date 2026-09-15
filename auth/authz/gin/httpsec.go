package gin

import (
	"log"
	"strings"
)

// RFC 6750 (Bearer Token Usage §3.1) defines a closed error-code vocabulary
// for the WWW-Authenticate challenge: invalid_request, invalid_token,
// insufficient_scope. This package never emits a 401/challenge response at
// all (G8-5, gap-analysis-final.md Tier 2 line 107: "authz emits 403 only
// ... Challenges are authn's job") -- a missing principal in context is
// answered with 403 like any other authorization failure, not a
// WWW-Authenticate challenge. Only "insufficient_scope" remains, and it is
// an OAuth *scope* error code (RFC 6750 §3.1) -- it is written into the
// WWW-Authenticate header solely by require.go's requireScopeGuard, which
// checks an actual scope requirement. Policy/PARC denials (handleResult's
// policy-fail path, requirePolicyGuard, requirePARCGuard) are not scope
// shortfalls, so they answer 403 with a Problem Details body only, no
// WWW-Authenticate header. (The former "unauthorized" auth-param value,
// this package's own non-RFC convention for "no authenticated principal is
// present", was removed with the 401 code paths that used it -- see
// require.go's requirePolicyGuard/requirePARCGuard/
// respondNoPrincipalForbidden and middleware.go's handleResult.)
//
// Tier 0 #7: the built-in response writers in this package
// (middleware.go's handleResult, require.go's requirePolicyGuard/
// requirePARCGuard/requireScopeGuard) must never place Decision.Reason /
// AuthorizationResult.FailureReason verbatim into the WWW-Authenticate
// header or the default JSON body. That value can be built from an
// arbitrary wrapped error -- e.g. a PermissionRepository/cache failure
// surfaces as err.Error() via authz/engine.go's Evaluate -- and can contain
// DB internals or characters (quotes, CR/LF) that break the header's
// quoted-string. Every error_description written by the default handlers in
// this package is a fixed literal; the real reason is logged server-side
// only via logAuthzDenial, never echoed to the caller. A caller-supplied
// ResultHandler is a different, explicit opt-in boundary and still
// receives the full, unsanitized AuthorizationResult -- sanitizing that
// path is this application's own choice, not this library's default.
const (
	rfc6750InsufficientScope = "insufficient_scope"
)

// Fixed, safe descriptions used by the default (non-custom) response
// writers. Never replaced with a Decision.Reason/FailureReason at runtime.
const (
	descAuthenticationRequired = "Authentication required"
	descAccessDeniedByPolicy   = "Access denied by policy"
)

// logAuthzDenial records the real, unsanitized authorization denial reason
// server-side only (Tier 0 #7's "log the real detail server-side only"
// requirement). Never called anywhere near a header or response body.
func logAuthzDenial(context, reason string) {
	log.Printf("authz: %s denied: %s", context, reason)
}

// quoteRFC7235 renders s as an RFC 7235 quoted-string for use as an
// auth-param value: wrapped in double quotes, with '"' and '\' backslash-
// escaped, and CR/LF/other control characters dropped outright (escaping
// them would still deliver them into the header value; RFC 7230 forbids
// them in a header field entirely). This is what stops a value containing
// a stray quote or embedded newline from truncating the auth-param early or
// injecting additional header fields / response content (Tier 0 #7).
func quoteRFC7235(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\r' || r == '\n' || r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
