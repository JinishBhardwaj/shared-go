package principal

import "testing"

// TestHasAnyScope_EmptyCandidateList_FailsClosed is the Tier 0 #6 regression test
// (gap-analysis-final.md: "HasAnyScope() / HasAnyRole() return true for an empty
// list, so ScopeRequirement{RequireAll:false, Scopes:nil} allows everything").
// An empty candidate list means "no acceptable scope was specified" -- the
// correct, fail-closed answer is deny (false), never allow (true).
func TestHasAnyScope_EmptyCandidateList_FailsClosed(t *testing.T) {
	p := &Principal{Subject: "user1", Scopes: []string{"read:reports", "write:orders"}}

	if got := p.HasAnyScope(); got {
		t.Errorf("HasAnyScope() with an empty candidate list = %v, want false (fail closed)", got)
	}
}

// TestHasAnyRole_EmptyCandidateList_FailsClosed is the Tier 0 #6 regression test
// for the role-side counterpart of the same defect.
func TestHasAnyRole_EmptyCandidateList_FailsClosed(t *testing.T) {
	p := &Principal{Subject: "user1", Roles: []string{"viewer"}}

	if got := p.HasAnyRole(); got {
		t.Errorf("HasAnyRole() with an empty candidate list = %v, want false (fail closed)", got)
	}
}

// TestHasAnyScope_NonEmptyCandidateList_StillWorks guards against a fix that
// over-corrects into always-deny: a genuine match must still allow.
func TestHasAnyScope_NonEmptyCandidateList_StillWorks(t *testing.T) {
	p := &Principal{Subject: "user1", Scopes: []string{"read:reports"}}

	if got := p.HasAnyScope("write:orders", "read:reports"); !got {
		t.Errorf("HasAnyScope() with a matching candidate = %v, want true", got)
	}
	if got := p.HasAnyScope("write:orders", "delete:orders"); got {
		t.Errorf("HasAnyScope() with no matching candidate = %v, want false", got)
	}
}

// TestHasAnyRole_NonEmptyCandidateList_StillWorks is the role-side counterpart.
func TestHasAnyRole_NonEmptyCandidateList_StillWorks(t *testing.T) {
	p := &Principal{Subject: "user1", Roles: []string{"viewer"}}

	if got := p.HasAnyRole("admin", "viewer"); !got {
		t.Errorf("HasAnyRole() with a matching candidate = %v, want true", got)
	}
	if got := p.HasAnyRole("admin", "editor"); got {
		t.Errorf("HasAnyRole() with no matching candidate = %v, want false", got)
	}
}
