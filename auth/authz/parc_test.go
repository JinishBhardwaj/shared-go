package authz

import "testing"

// TestPermissionRule_TenantFailClosed is the Tier 0 #1 regression test
// (gap-analysis-final.md: "Tenant check skipped when req.Resource.TenantID
// == ” -- any extractor that omits TenantID bypasses tenant isolation").
// A rule pinned to a specific tenant must NEVER match a request whose
// Resource.TenantID is empty -- that is a missing/omitted tenant on the
// request side, not "any tenant is fine".
func TestPermissionRule_TenantFailClosed(t *testing.T) {
	pinnedRule := PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "*",
		TenantID:          "tenant_a",
		Effect:            EffectPermit,
	}

	t.Run("pinned rule, empty request tenant -> no match (fail closed)", func(t *testing.T) {
		req := Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "report", ID: "rep_1", TenantID: ""},
		}
		if pinnedRule.Matches(req) {
			t.Errorf("expected pinned rule NOT to match a request with an empty tenant, but it matched")
		}
	})

	t.Run("pinned rule, matching request tenant -> match", func(t *testing.T) {
		req := Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "report", ID: "rep_1", TenantID: "tenant_a"},
		}
		if !pinnedRule.Matches(req) {
			t.Errorf("expected pinned rule to match a request with the same tenant")
		}
	})

	t.Run("pinned rule, mismatched request tenant -> no match", func(t *testing.T) {
		req := Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "report", ID: "rep_1", TenantID: "tenant_b"},
		}
		if pinnedRule.Matches(req) {
			t.Errorf("expected pinned rule NOT to match a request with a different tenant")
		}
	})

	t.Run("unpinned rule (empty TenantID), any request tenant -> match", func(t *testing.T) {
		unpinnedRule := PermissionRule{
			ActionPattern:     "read",
			ResourceType:      "report",
			ResourceIDPattern: "*",
			Effect:            EffectPermit,
		}
		req := Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "report", ID: "rep_1", TenantID: "tenant_z"},
		}
		if !unpinnedRule.Matches(req) {
			t.Errorf("expected unpinned rule to match regardless of request tenant")
		}
	})

	t.Run("wildcard rule (TenantID '*'), any request tenant -> match", func(t *testing.T) {
		wildcardRule := PermissionRule{
			ActionPattern:     "read",
			ResourceType:      "report",
			ResourceIDPattern: "*",
			TenantID:          "*",
			Effect:            EffectPermit,
		}
		req := Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "report", ID: "rep_1", TenantID: ""},
		}
		if !wildcardRule.Matches(req) {
			t.Errorf("expected TenantID:'*' rule to match even an empty request tenant")
		}
	})
}

// TestMatchGlob_EmptyPatternFailsClosed is the Tier 0 #2 regression test
// (gap-analysis-final.md: "matchGlob returns true for an empty pattern --
// a blank ActionPattern/ResourceIDPattern in a DB row silently becomes
// '*'"). Only the literal "*" may mean wildcard; an empty pattern must
// never match anything.
func TestMatchGlob_EmptyPatternFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		val     string
		want    bool
	}{
		{"empty pattern, empty value -> no match", "", "", false},
		{"empty pattern, non-empty value -> no match", "", "read", false},
		{"literal wildcard, any value -> match", "*", "read", true},
		{"literal wildcard, empty value -> match", "*", "", true},
		{"exact match", "read", "read", true},
		{"exact mismatch", "read", "write", false},
		{"glob match", "reports:*", "reports:export", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchGlob(tc.pattern, tc.val)
			if got != tc.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.val, got, tc.want)
			}
		})
	}
}

// TestPermissionRule_EmptyActionPatternFailsClosed exercises Tier 0 #2 at
// the PermissionRule.Matches level: a blank ActionPattern (e.g. a
// zero-valued or corrupted DB row) must not silently authorize every
// action.
func TestPermissionRule_EmptyActionPatternFailsClosed(t *testing.T) {
	rule := PermissionRule{
		ActionPattern:     "",
		ResourceType:      "report",
		ResourceIDPattern: "*",
		Effect:            EffectPermit,
	}
	req := Request{
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "report", ID: "rep_1"},
	}
	if rule.Matches(req) {
		t.Errorf("expected rule with empty ActionPattern NOT to match, but it matched")
	}
}
