// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package consumer

import (
	"errors"
	"strings"
	"testing"
)

func TestAuthBinding_NormalizeAndValidate(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.AuthBinding = &AuthBinding{
		AllowedClientIDs:           []string{" app-a ", "", "app-a", "app-b"},
		AllowedCertificateSubjects: []string{"svc.internal", " svc.internal"},
	}
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(c.AuthBinding.AllowedClientIDs) != 2 || c.AuthBinding.AllowedClientIDs[0] != "app-a" || c.AuthBinding.AllowedClientIDs[1] != "app-b" {
		t.Fatalf("client ids must be trimmed and de-duplicated in order, got %v", c.AuthBinding.AllowedClientIDs)
	}
	if len(c.AuthBinding.AllowedCertificateSubjects) != 1 {
		t.Fatalf("subjects must be de-duplicated, got %v", c.AuthBinding.AllowedCertificateSubjects)
	}

	tooMany := make([]string, maxAuthBindingEntries+1)
	for i := range tooMany {
		tooMany[i] = "client-" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
	}
	if err := (AuthBinding{AllowedClientIDs: tooMany}).Validate(); !errors.Is(err, ErrInvalidAuthBinding) {
		t.Fatalf("err = %v, want ErrInvalidAuthBinding for too many entries", err)
	}
	if err := (AuthBinding{AllowedCertificateSubjects: []string{strings.Repeat("a", maxAuthBindingEntryLength+1)}}).Validate(); !errors.Is(err, ErrInvalidAuthBinding) {
		t.Fatalf("err = %v, want ErrInvalidAuthBinding for a long entry", err)
	}
}

func TestAuthBinding_AllowsClient(t *testing.T) {
	t.Parallel()
	open := AuthBinding{}
	if !open.AllowsClient(nil) || !open.AllowsClient(map[string]any{"azp": "anyone"}) {
		t.Fatal("without an allowed list every client passes")
	}
	bound := AuthBinding{AllowedClientIDs: []string{"app-a"}}
	if !bound.AllowsClient(map[string]any{"azp": "app-a"}) {
		t.Fatal("azp in the list must pass")
	}
	if !bound.AllowsClient(map[string]any{"client_id": "app-a"}) {
		t.Fatal("client_id in the list must pass when azp is absent")
	}
	if bound.AllowsClient(map[string]any{"azp": "app-b", "client_id": "app-a"}) {
		t.Fatal("azp wins over client_id: a token issued to another client must fail")
	}
	if bound.AllowsClient(map[string]any{"sub": "user"}) || bound.AllowsClient(nil) {
		t.Fatal("a token without a client claim cannot satisfy a binding")
	}
}

func TestAuthBinding_AllowsCertificate(t *testing.T) {
	t.Parallel()
	open := AuthBinding{}
	if !open.AllowsCertificate("", nil) {
		t.Fatal("without an allowed list every verified certificate passes")
	}
	bound := AuthBinding{AllowedCertificateSubjects: []string{"svc.internal", "batch-runner"}}
	if !bound.AllowsCertificate("batch-runner", nil) {
		t.Fatal("common name in the list must pass")
	}
	if !bound.AllowsCertificate("other", []string{"x", "svc.internal"}) {
		t.Fatal("a SAN DNS name in the list must pass")
	}
	if bound.AllowsCertificate("other", []string{"nope"}) || bound.AllowsCertificate("", nil) {
		t.Fatal("a certificate naming none of the subjects must fail")
	}
}

func TestClientOfClaims(t *testing.T) {
	t.Parallel()
	if got := ClientOfClaims(map[string]any{"azp": " app "}); got != "app" {
		t.Fatalf("ClientOfClaims = %q, want trimmed azp", got)
	}
	if got := ClientOfClaims(map[string]any{"client_id": 42}); got != "" {
		t.Fatalf("ClientOfClaims = %q, want empty for a non-string claim", got)
	}
}

func TestAuthBinding_AllowsCertificateClaims(t *testing.T) {
	t.Parallel()
	bound := AuthBinding{AllowedCertificateSubjects: []string{"svc.internal"}}
	if !bound.AllowsCertificateClaims(map[string]any{"common_name": "other", "dns_names": []any{"svc.internal"}}) {
		t.Fatal("a SAN in the claims (decoded as []any) must pass")
	}
	if !bound.AllowsCertificateClaims(map[string]any{"common_name": "svc.internal", "dns_names": []string{}}) {
		t.Fatal("the common name in the claims must pass")
	}
	if bound.AllowsCertificateClaims(map[string]any{"common_name": "other"}) || bound.AllowsCertificateClaims(nil) {
		t.Fatal("claims naming no allowed subject must fail")
	}
	if !(AuthBinding{}).AllowsCertificateClaims(nil) {
		t.Fatal("without an allowed list every certificate passes")
	}
}

func TestAuthBinding_ClaimRulesNormalizeAndValidate(t *testing.T) {
	t.Parallel()
	b := AuthBinding{
		RequiredClaims:  map[string][]string{" idtyp ": {" app ", "app", ""}, "  ": {"dropped"}},
		ForbiddenClaims: []string{" email", "email", "upn", ""},
	}
	b.Normalize()
	if len(b.RequiredClaims) != 1 || len(b.RequiredClaims["idtyp"]) != 1 || b.RequiredClaims["idtyp"][0] != "app" {
		t.Fatalf("required claims must be trimmed and de-duplicated, got %v", b.RequiredClaims)
	}
	if len(b.ForbiddenClaims) != 2 || b.ForbiddenClaims[0] != "email" || b.ForbiddenClaims[1] != "upn" {
		t.Fatalf("forbidden claims must be trimmed and de-duplicated in order, got %v", b.ForbiddenClaims)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if b.IsZero() {
		t.Fatal("a binding with claim rules narrows something")
	}

	invalid := map[string]AuthBinding{
		"whitespace in a forbidden claim":   {ForbiddenClaims: []string{"bad name"}},
		"long claim name":                   {ForbiddenClaims: []string{strings.Repeat("c", maxClaimNameLength+1)}},
		"whitespace in a required claim":    {RequiredClaims: map[string][]string{"bad name": nil}},
		"long required value":               {RequiredClaims: map[string][]string{"idtyp": {strings.Repeat("v", maxAuthBindingEntryLength+1)}}},
		"claim both required and forbidden": {RequiredClaims: map[string][]string{"email": nil}, ForbiddenClaims: []string{"email"}},
	}
	tooManyValues := make([]string, maxClaimValuesPerClaim+1)
	for i := range tooManyValues {
		tooManyValues[i] = strings.Repeat("v", i+1)
	}
	invalid["too many values"] = AuthBinding{RequiredClaims: map[string][]string{"roles": tooManyValues}}
	tooManyClaims := make([]string, maxClaimRules+1)
	for i := range tooManyClaims {
		tooManyClaims[i] = "claim" + strings.Repeat("x", i)
	}
	invalid["too many forbidden claims"] = AuthBinding{ForbiddenClaims: tooManyClaims}
	for name, b := range invalid {
		if err := b.Validate(); !errors.Is(err, ErrInvalidAuthBinding) {
			t.Errorf("%s: err = %v, want ErrInvalidAuthBinding", name, err)
		}
	}
}

func TestAuthBinding_AllowsClaims(t *testing.T) {
	t.Parallel()
	machineOnly := AuthBinding{
		ForbiddenClaims: []string{"email", "upn", "name", "preferred_username"},
		RequiredClaims:  map[string][]string{"idtyp": {"app"}},
	}
	cases := []struct {
		name    string
		binding AuthBinding
		claims  map[string]any
		want    bool
	}{
		{"no rules admit anything", AuthBinding{}, map[string]any{"email": "a@b.c"}, true},
		{"workload token passes", machineOnly, map[string]any{"sub": "agent", "idtyp": "app"}, true},
		{"a person's token is refused", machineOnly, map[string]any{"sub": "u", "idtyp": "app", "upn": "u@corp"}, false},
		{"an empty forbidden claim says nothing", machineOnly, map[string]any{"idtyp": "app", "email": ""}, true},
		{"a null forbidden claim says nothing", machineOnly, map[string]any{"idtyp": "app", "name": nil}, true},
		{"missing required claim", machineOnly, map[string]any{"sub": "agent"}, false},
		{"wrong required value", machineOnly, map[string]any{"idtyp": "user"}, false},
		{"array claim matches an element", AuthBinding{RequiredClaims: map[string][]string{"roles": {"agent"}}}, map[string]any{"roles": []any{"reader", "agent"}}, true},
		{"array claim without the value", AuthBinding{RequiredClaims: map[string][]string{"roles": {"agent"}}}, map[string]any{"roles": []any{"reader"}}, false},
		{"empty array is not present", AuthBinding{RequiredClaims: map[string][]string{"roles": nil}}, map[string]any{"roles": []any{}}, false},
		{"presence only", AuthBinding{RequiredClaims: map[string][]string{"oid": nil}}, map[string]any{"oid": "abc"}, true},
		{"boolean compared in its JSON spelling", AuthBinding{RequiredClaims: map[string][]string{"agent": {"true"}}}, map[string]any{"agent": true}, true},
		{"number compared in its JSON spelling", AuthBinding{RequiredClaims: map[string][]string{"ver": {"2"}}}, map[string]any{"ver": float64(2)}, true},
		{"object never matches", AuthBinding{RequiredClaims: map[string][]string{"x": {"y"}}}, map[string]any{"x": map[string]any{"y": "y"}}, false},
	}
	for _, tc := range cases {
		if got := tc.binding.AllowsClaims(tc.claims); got != tc.want {
			t.Errorf("%s: AllowsClaims = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAuthBinding_AllowsTokenCombinesClientAndClaims(t *testing.T) {
	t.Parallel()
	b := AuthBinding{AllowedClientIDs: []string{"agent-app"}, ForbiddenClaims: []string{"upn"}}
	if !b.AllowsToken(map[string]any{"azp": "agent-app"}) {
		t.Fatal("allowed client without forbidden claims must pass")
	}
	if b.AllowsToken(map[string]any{"azp": "agent-app", "upn": "someone@corp"}) {
		t.Fatal("a delegated token issued to the allowed client must still be refused")
	}
	if b.AllowsToken(map[string]any{"azp": "other"}) {
		t.Fatal("another client must be refused")
	}
}
