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

package storeaccess

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestNewPolicyValidates(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	p, err := NewPolicy(gw, PrincipalUser, " ana ", " Curated ")
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	if p.PrincipalID != "ana" || p.Mode != "curated" {
		t.Fatalf("policy must be normalised, got %+v", p)
	}
	for _, bad := range []struct {
		gw   ids.GatewayID
		typ  PrincipalType
		id   string
		mode string
	}{
		{ids.GatewayID{}, PrincipalUser, "ana", "open"},
		{gw, "team", "ana", "open"},
		{gw, PrincipalGroup, "", "open"},
		{gw, PrincipalUser, "ana", "everything"},
	} {
		if _, err := NewPolicy(bad.gw, bad.typ, bad.id, bad.mode); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("%+v must be invalid, got %v", bad, err)
		}
	}
}

func TestPolicySetPrecedence(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	mk := func(typ PrincipalType, id, mode string) *Policy {
		p, _ := NewPolicy(gw, typ, id, mode)
		return p
	}
	set := IndexPolicies([]*Policy{
		mk(PrincipalUser, "ana", "none"),
		mk(PrincipalGroup, "eng", "curated"),
		mk(PrincipalGroup, "sre", "open"),
		{GatewayID: gw, PrincipalType: PrincipalGroup, PrincipalID: "bogus", Mode: "everything"},
		nil,
	})
	if got := set.Mode("ana", []string{"sre"}); got != "none" {
		t.Fatalf("own policy must win over groups, got %q", got)
	}
	if got := set.Mode("bob", []string{"eng", "sre"}); got != "open" {
		t.Fatalf("most permissive group must win, got %q", got)
	}
	if got := set.Mode("bob", []string{"eng"}); got != "curated" {
		t.Fatalf("single group policy applies, got %q", got)
	}
	if got := set.Mode("bob", []string{"marketing", "bogus"}); got != "" {
		t.Fatalf("no matching policy (invalid ones skipped) must yield none, got %q", got)
	}
	var nilSet *PolicySet
	if nilSet.Mode("ana", nil) != "" {
		t.Fatal("a nil set has no policy")
	}
}
