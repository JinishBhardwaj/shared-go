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

// TestPermissionRule_ActionMatchesLogicalNameOnly is the Tier 1 line 98
// regression test ("Unify action semantics"). Before this fix, Matches
// accepted either Action.Name (the logical action) or Action.HTTPMethod (the
// raw HTTP verb) -- so a rule authored against one action model silently
// granted the other. A rule pinned to the raw verb "GET" must never match a
// request whose logical Action.Name is "read" (even though the request also
// carries HTTPMethod "GET"), and a rule pinned to the logical action "read"
// must never match a request whose logical Action.Name is something else
// just because its HTTPMethod happens to be "GET".
func TestPermissionRule_ActionMatchesLogicalNameOnly(t *testing.T) {
	rawVerbRule := PermissionRule{
		ActionPattern:     "GET",
		ResourceType:      "report",
		ResourceIDPattern: "*",
		Effect:            EffectPermit,
	}
	logicalReadRequest := Request{
		Action:   Action{Name: "read", HTTPMethod: "GET"},
		Resource: Resource{Type: "report", ID: "rep_1"},
	}
	if rawVerbRule.Matches(logicalReadRequest) {
		t.Errorf("expected a rule pinned to the raw verb 'GET' NOT to match a request whose logical action is 'read', but it matched via HTTPMethod")
	}

	logicalActionRule := PermissionRule{
		ActionPattern:     "read",
		ResourceType:      "report",
		ResourceIDPattern: "*",
		Effect:            EffectPermit,
	}
	rawMethodOnlyRequest := Request{
		// A request whose logical action was never set to "read" (e.g. a
		// caller that only ever populated HTTPMethod) must not be granted by
		// a rule pinned to the logical action "read" just because the two
		// strings happen to be unrelated but HTTPMethod leaked through.
		Action:   Action{Name: "some_other_logical_action", HTTPMethod: "GET"},
		Resource: Resource{Type: "report", ID: "rep_1"},
	}
	if logicalActionRule.Matches(rawMethodOnlyRequest) {
		t.Errorf("expected a rule pinned to the logical action 'read' NOT to match a request whose Action.Name is unrelated, but it matched via HTTPMethod")
	}

	matchingRequest := Request{
		Action:   Action{Name: "read", HTTPMethod: "GET"},
		Resource: Resource{Type: "report", ID: "rep_1"},
	}
	if !logicalActionRule.Matches(matchingRequest) {
		t.Errorf("expected a rule pinned to the logical action 'read' to match a request whose Action.Name is 'read'")
	}
}
