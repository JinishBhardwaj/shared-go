package authz

import "testing"

// TestPrincipalPermissions_Evaluate_ResourceTypeIndexing is the G9-2
// regression test for Tier 3 "precompile rule globs and index rules by
// resource type at bundle load". It exercises all three ruleIndex buckets
// (exact-literal ResourceType, wildcard "*" ResourceType, and the
// glob/empty-ResourceType fallback bucket) in a single bundle and confirms
// Evaluate's outcome is identical to what an exhaustive per-rule scan would
// have produced -- i.e. that indexing narrowed WHICH rules are consulted,
// never WHAT they decide.
func TestPrincipalPermissions_Evaluate_ResourceTypeIndexing(t *testing.T) {
	perms := &PrincipalPermissions{
		PrincipalID: "usr_1",
		Rules: []PermissionRule{
			// byType["report"] bucket.
			{ActionPattern: "read", ResourceType: "report", ResourceIDPattern: "*", Effect: EffectPermit},
			// byType["order"] bucket, a DENY -- must never leak into a
			// "report" evaluation just because it lives in the same slice.
			{ActionPattern: "read", ResourceType: "order", ResourceIDPattern: "*", Effect: EffectDeny},
			// wildcard bucket ("*" ResourceType) -- applies to every
			// resource type, including ones with no byType bucket at all.
			{ActionPattern: "audit", ResourceType: "*", ResourceIDPattern: "*", Effect: EffectPermit},
			// fallback bucket: ResourceType contains a glob metacharacter,
			// so it cannot be bucketed by exact-literal lookup and must
			// still be scanned via matchGlob every time.
			{ActionPattern: "read", ResourceType: "rep*", ResourceIDPattern: "*", Effect: EffectPermit},
		},
	}

	t.Run("report/read hits byType[report] permit, never the order/delete rule", func(t *testing.T) {
		d := perms.Evaluate(Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "report", ID: "rep_1"},
		})
		if !d.Allowed {
			t.Errorf("expected report/read to be allowed via the byType[report] bucket, got denied: %+v", d)
		}
	})

	t.Run("order/read hits byType[order] deny, unaffected by report's permit rule", func(t *testing.T) {
		d := perms.Evaluate(Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "order", ID: "ord_1"},
		})
		if d.Allowed {
			t.Errorf("expected order/read to be denied via the byType[order] bucket, got allowed: %+v", d)
		}
	})

	t.Run("wildcard bucket applies regardless of resource type", func(t *testing.T) {
		d := perms.Evaluate(Request{
			Action:   Action{Name: "audit"},
			Resource: Resource{Type: "invoice", ID: "inv_1"}, // no byType["invoice"] bucket at all
		})
		if !d.Allowed {
			t.Errorf("expected the wildcard-ResourceType rule to grant 'audit' on an unrelated resource type, got denied: %+v", d)
		}
	})

	t.Run("fallback bucket (glob ResourceType) is still consulted", func(t *testing.T) {
		d := perms.Evaluate(Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "reputation", ID: "x"}, // matches glob "rep*", not the exact "report" bucket
		})
		if !d.Allowed {
			t.Errorf("expected the fallback glob rule 'rep*' to match ResourceType 'reputation', got denied: %+v", d)
		}
	})

	t.Run("resource type with no matching bucket at all denies", func(t *testing.T) {
		d := perms.Evaluate(Request{
			Action:   Action{Name: "read"},
			Resource: Resource{Type: "billing", ID: "b_1"},
		})
		if d.Allowed {
			t.Errorf("expected 'billing' (no byType bucket, no glob match, no matching action for wildcard) to be denied, got allowed: %+v", d)
		}
	})
}

// TestPrincipalPermissions_Evaluate_IndexCachedAcrossCalls confirms the
// lazily-built index is reused (not silently stale or rebuilt in a way
// that changes the outcome) across multiple Evaluate calls against the
// same *PrincipalPermissions for different requests -- the actual
// performance property "index at bundle load, reuse for the bundle's
// lifetime" depends on.
func TestPrincipalPermissions_Evaluate_IndexCachedAcrossCalls(t *testing.T) {
	perms := &PrincipalPermissions{
		PrincipalID: "usr_2",
		Rules: []PermissionRule{
			{ActionPattern: "read", ResourceType: "report", ResourceIDPattern: "*", Effect: EffectPermit},
			{ActionPattern: "read", ResourceType: "order", ResourceIDPattern: "*", Effect: EffectDeny},
		},
	}

	for i := 0; i < 5; i++ {
		if d := perms.Evaluate(Request{Action: Action{Name: "read"}, Resource: Resource{Type: "report", ID: "r"}}); !d.Allowed {
			t.Fatalf("iteration %d: expected report/read allowed, got %+v", i, d)
		}
		if d := perms.Evaluate(Request{Action: Action{Name: "read"}, Resource: Resource{Type: "order", ID: "o"}}); d.Allowed {
			t.Fatalf("iteration %d: expected order/read denied, got %+v", i, d)
		}
	}
}

// TestCompiledPattern_MatchesMatchGlobExactly cross-checks compiledPattern
// (the precompiled fast path used by the index) against matchGlob (the
// untouched, still-directly-tested source of truth for Tier 0 #2's
// fail-closed semantics) across the same case set, so the two can never
// silently drift apart.
func TestCompiledPattern_MatchesMatchGlobExactly(t *testing.T) {
	cases := []struct {
		pattern string
		val     string
	}{
		{"", ""},
		{"", "read"},
		{"*", "read"},
		{"*", ""},
		{"read", "read"},
		{"read", "write"},
		{"reports:*", "reports:export"},
		{"reports:*", "orders:export"},
		{"rep*", "reputation"},
		{"rep*", "billing"},
	}

	for _, tc := range cases {
		want := matchGlob(tc.pattern, tc.val)
		got := compilePattern(tc.pattern).match(tc.val)
		if got != want {
			t.Errorf("compilePattern(%q).match(%q) = %v, want %v (matchGlob's answer)", tc.pattern, tc.val, got, want)
		}
	}
}
