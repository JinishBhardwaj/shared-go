package authz

import (
	"sync"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/principal"
)

// TestMapPARCPrincipal_ConcurrentAccessIsRaceFree guards against a regression
// of the G4 data race fixed alongside this test: EvaluationContext.mu must
// serialize reads/writes of mappedPrincipal/mappedPrincipalFor so concurrent
// requirement-handler evaluation against one EvaluationContext is safe under
// `go test -race`. -race caught the original unsynchronized access
// incidentally during G5 testing (a test that shared one EvaluationContext
// across goroutines, since fixed to use per-goroutine contexts instead); this
// test exercises the same shape deliberately, directly against
// mapPARCPrincipal, so the underlying engine.go fix has its own dedicated,
// standalone regression coverage independent of that test's shape.
//
// Confirmed red (flagged by -race) against the pre-fix mapPARCPrincipal
// (no mutex, unsynchronized read/write of the two cache fields); green
// after adding EvaluationContext.mu.
func TestMapPARCPrincipal_ConcurrentAccessIsRaceFree(t *testing.T) {
	p := &principal.Principal{
		Subject:  "race-user",
		ClientID: "race-client",
		Roles:    []string{"admin"},
		Scopes:   []string{"read"},
		Method:   principal.AuthMethodClientCredentials,
		Metadata: map[string]any{"tenant": "acme"},
	}
	evalCtx := &EvaluationContext{}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			mapped := mapPARCPrincipal(evalCtx, p)
			if mapped.ID != p.Subject {
				t.Errorf("mapped.ID = %q, want %q", mapped.ID, p.Subject)
			}
		}()
	}
	wg.Wait()
}
