package authtest

import (
	"errors"

	authngin "github.com/JinishBhardwaj/shared-go/auth/authn/gin"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/gin-gonic/gin"
)

// ErrNilPrincipal is returned by NewNoopAuthenticator when p is nil.
var ErrNilPrincipal = errors.New("authtest: NewNoopAuthenticator requires a non-nil principal")

// NoopAuthenticator implements authngin.Authenticator by returning a fixed
// Principal for every request, performing no credential extraction or
// token/key validation at all. It exists for local/dev-mode bootstrapping
// where standing up even MockOAuthProvider's mock IdP flow is unnecessary
// friction.
//
// NEVER wire this into a production authentication pipeline: a request
// reaching it is authenticated as the configured Principal regardless of
// what credentials, if any, it presents.
type NoopAuthenticator struct {
	principal *principal.Principal
}

var _ authngin.Authenticator = (*NoopAuthenticator)(nil)

// NewNoopAuthenticator returns a NoopAuthenticator that authenticates every
// request as p. p must be non-nil: authz.PolicyEngine.Evaluate denies on a
// nil Principal, which would make every policy-gated route fail closed
// instead of the intended "everything through as this identity" bypass.
func NewNoopAuthenticator(p *principal.Principal) (*NoopAuthenticator, error) {
	if p == nil {
		return nil, ErrNilPrincipal
	}
	return &NoopAuthenticator{principal: p}, nil
}

// Authenticate implements authngin.Authenticator. It ignores c entirely and
// always returns the Principal configured at construction.
func (n *NoopAuthenticator) Authenticate(c *gin.Context) (*principal.Principal, error) {
	return n.principal, nil
}
