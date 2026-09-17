package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/JinishBhardwaj/shared-go/auth/authn/mapping"
	"github.com/JinishBhardwaj/shared-go/auth/principal"
	"github.com/golang-jwt/jwt/v5"
)

type stubIDTokenVerifier struct {
	claims jwt.MapClaims
	err    error
}

func (s stubIDTokenVerifier) VerifyClaims(ctx context.Context, tokenStr string) (jwt.MapClaims, error) {
	return s.claims, s.err
}

func TestIDTokenGroupsEnricher_MergesGroupsFromIDToken(t *testing.T) {
	enricher := &IDTokenGroupsEnricher{
		verifier: stubIDTokenVerifier{claims: jwt.MapClaims{
			"custom:groups": "[domains-tcc-access, domains-iuxp-access]",
		}},
		extractors: []mapping.GroupsExtractor{mapping.NewCognitoCustomAttrListExtractor("custom:groups")},
	}

	p := &principal.Principal{Subject: "u1", Roles: []string{"grafana-stg-users"}}

	out := enricher.Enrich(context.Background(), "some.id.token", p)

	if out == p {
		t.Fatal("expected Enrich to return a copy, not mutate the input Principal")
	}
	if len(p.Roles) != 1 {
		t.Fatalf("input Principal must not be mutated, got roles: %v", p.Roles)
	}
	for _, want := range []string{"grafana-stg-users", "domains-tcc-access", "domains-iuxp-access"} {
		if !out.HasRole(want) {
			t.Errorf("expected role %q, got: %v", want, out.Roles)
		}
	}
}

func TestIDTokenGroupsEnricher_VerificationFailureDegradesToNoOp(t *testing.T) {
	enricher := &IDTokenGroupsEnricher{
		verifier:   stubIDTokenVerifier{err: errors.New("boom: forged or expired id token")},
		extractors: []mapping.GroupsExtractor{mapping.NewCognitoCustomAttrListExtractor("custom:groups")},
	}

	p := &principal.Principal{Subject: "u1", Roles: []string{"grafana-stg-users"}}

	out := enricher.Enrich(context.Background(), "some.id.token", p)

	if out != p {
		t.Error("expected verification failure to return the original principal unchanged")
	}
}

func TestIDTokenGroupsEnricher_EmptyIDTokenIsNoOp(t *testing.T) {
	enricher := &IDTokenGroupsEnricher{
		verifier: stubIDTokenVerifier{err: errors.New("must not be called")},
	}
	p := &principal.Principal{Subject: "u1"}

	if out := enricher.Enrich(context.Background(), "", p); out != p {
		t.Error("expected empty ID token to be a no-op")
	}
}
