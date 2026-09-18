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

package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

var (
	snowflake = ids.New[ids.RegistryKind]()
	jira      = ids.New[ids.RegistryKind]()
)

func runQuery() MCPTarget { return MCPTarget{RegistryID: snowflake, Tool: "run_query"} }

func finance() MCPCaller { return MCPCaller{Groups: []string{"Finanzas"}} }

func marketing() MCPCaller { return MCPCaller{Groups: []string{"Marketing"}} }

func TestMCPScope_Specificity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		scope *MCPScope
		want  uint8
	}{
		{name: "nil", scope: nil, want: 0},
		{name: "empty", scope: &MCPScope{}, want: 0},
		{name: "principal only", scope: &MCPScope{Groups: []string{"Finanzas"}}, want: 1},
		{name: "except only counts as principal", scope: &MCPScope{ExceptGroups: []string{"Finanzas"}}, want: 1},
		{name: "registry", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}, want: 2},
		{name: "registry and principal", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Groups: []string{"Finanzas"}}, want: 3},
		{name: "tool", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}}, want: 4},
		{name: "tool beats registry", scope: &MCPScope{RegistryIDs: []ids.RegistryID{jira}, Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}}, want: 4},
		{name: "tool and principal", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}, Groups: []string{"Finanzas"}}, want: 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.Specificity(); got != tc.want {
				t.Fatalf("Specificity() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMCPScope_Predicates(t *testing.T) {
	t.Parallel()
	var nilScope *MCPScope
	if nilScope.IsEmpty() || nilScope.HasDestination() || nilScope.HasPrincipal() {
		t.Fatal("nil scope must report no emptiness, destination or principal")
	}
	empty := &MCPScope{}
	if !empty.IsEmpty() || empty.HasDestination() || empty.HasPrincipal() {
		t.Fatal("{} must be empty with neither destination nor principal")
	}
	dest := &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}
	if dest.IsEmpty() || !dest.HasDestination() || dest.HasPrincipal() {
		t.Fatal("registry scope must have destination only")
	}
	principal := &MCPScope{ExceptGroups: []string{"Finanzas"}}
	if principal.IsEmpty() || principal.HasDestination() || !principal.HasPrincipal() {
		t.Fatal("except_groups scope must have principal only")
	}
}

func TestMCPScope_MatchesTarget(t *testing.T) {
	t.Parallel()
	exposed := MCPTarget{RegistryID: snowflake, Tool: "mcp_ab12cd34_run_query_9f8e7d6c"}
	tests := []struct {
		name   string
		scope  *MCPScope
		target MCPTarget
		want   bool
	}{
		{name: "no destination accepts any target", scope: &MCPScope{Groups: []string{"Finanzas"}}, target: runQuery(), want: true},
		{name: "registry match", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}, target: runQuery(), want: true},
		{name: "registry mismatch", scope: &MCPScope{RegistryIDs: []ids.RegistryID{jira}}, target: runQuery(), want: false},
		{name: "registry match ignores tool", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}, target: MCPTarget{RegistryID: snowflake, Tool: "delete_table"}, want: true},
		{name: "native tool match", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}}, target: runQuery(), want: true},
		{name: "same tool on another registry", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: jira, Tool: "run_query"}}}, target: runQuery(), want: false},
		{name: "other tool on same registry", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "delete_table"}}}, target: runQuery(), want: false},
		{name: "exposed federated name does not match", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}}, target: exposed, want: false},
		{name: "registry list or tool list", scope: &MCPScope{RegistryIDs: []ids.RegistryID{jira}, Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}}, target: runQuery(), want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.MatchesTarget(tc.target); got != tc.want {
				t.Fatalf("MatchesTarget(%+v) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}

// groupless is a caller whose identity carries no groups and still faces the
// principal dimension: a bearer token from an identity provider that emits no
// groups claim. apiKey is the one caller for which the dimension is inert.
func TestMCPScope_MatchesCaller(t *testing.T) {
	t.Parallel()
	groupless := MCPCaller{}
	apiKey := MCPCaller{PrincipalInert: true}
	tests := []struct {
		name    string
		scope   *MCPScope
		caller  MCPCaller
		want    bool
		wantWhy SkipReason
	}{
		{name: "no principal accepts anyone", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}, caller: groupless, want: true},
		{name: "no principal accepts an inert caller too", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}, caller: apiKey, want: true},
		{name: "group is case sensitive", scope: &MCPScope{Groups: []string{"Finanzas"}}, caller: MCPCaller{Groups: []string{"finanzas"}}, want: false, wantWhy: SkipPrincipal},
		{name: "one of several caller groups", scope: &MCPScope{Groups: []string{"Finanzas"}}, caller: MCPCaller{Groups: []string{"Marketing", "Finanzas"}}, want: true},
		{name: "group match", scope: &MCPScope{Groups: []string{"Finanzas"}}, caller: finance(), want: true},
		{name: "group with surrounding spaces in token", scope: &MCPScope{Groups: []string{"Finanzas"}}, caller: MCPCaller{Groups: []string{" Finanzas "}}, want: true},
		{name: "group mismatch", scope: &MCPScope{Groups: []string{"Finanzas"}}, caller: marketing(), want: false, wantWhy: SkipPrincipal},
		{name: "token without a groups claim never matches groups", scope: &MCPScope{Groups: []string{"Finanzas"}}, caller: groupless, want: false, wantWhy: SkipPrincipal},
		{name: "api key matches groups it does not have: the principal is inert", scope: &MCPScope{Groups: []string{"Finanzas"}}, caller: apiKey, want: true},
		{name: "any of the scoped groups", scope: &MCPScope{Groups: []string{"Finanzas", "Marketing"}}, caller: marketing(), want: true},
		{name: "everyone but Finanzas: Marketing", scope: &MCPScope{ExceptGroups: []string{"Finanzas"}}, caller: marketing(), want: true},
		{name: "everyone but Finanzas: Finanzas", scope: &MCPScope{ExceptGroups: []string{"Finanzas"}}, caller: finance(), want: false, wantWhy: SkipExcept},
		{name: "everyone but Finanzas: token without a groups claim", scope: &MCPScope{ExceptGroups: []string{"Finanzas"}}, caller: groupless, want: true},
		{name: "everyone but Finanzas: api key, unchanged by the inert principal", scope: &MCPScope{ExceptGroups: []string{"Finanzas"}}, caller: apiKey, want: true},
		// The inert branch skips the exception too. It is only equivalent to the
		// behaviour before the rule because the callers projected as inert carry
		// no groups: this case pins what would change if one ever did, which is
		// the deny-list direction the rule is not supposed to touch.
		{name: "inert caller carrying the excluded group is no longer excluded", scope: &MCPScope{ExceptGroups: []string{"Finanzas"}}, caller: MCPCaller{Groups: []string{"Finanzas"}, PrincipalInert: true}, want: true},
		{name: "positive match then excluded", scope: &MCPScope{Groups: []string{"Finanzas", "Marketing"}, ExceptGroups: []string{"Marketing"}}, caller: marketing(), want: false, wantWhy: SkipExcept},
		{name: "positive match not excluded", scope: &MCPScope{Groups: []string{"Finanzas"}, ExceptGroups: []string{"Marketing"}}, caller: finance(), want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, why := tc.scope.MatchesCaller(tc.caller)
			if got != tc.want || why != tc.wantWhy {
				t.Fatalf("MatchesCaller(%+v) = (%v, %q), want (%v, %q)", tc.caller, got, why, tc.want, tc.wantWhy)
			}
		})
	}
}

func TestMCPScope_Matches(t *testing.T) {
	t.Parallel()
	dlpFinance := &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Groups: []string{"Finanzas"}}
	onlyNotFinance := &MCPScope{
		Tools:        []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}},
		ExceptGroups: []string{"Finanzas"},
	}
	tests := []struct {
		name    string
		scope   *MCPScope
		target  MCPTarget
		caller  MCPCaller
		want    bool
		wantWhy SkipReason
	}{
		{name: "nil scope applies to everything", scope: nil, target: runQuery(), caller: MCPCaller{}, want: true},
		{name: "empty scope matches nothing", scope: &MCPScope{}, target: runQuery(), caller: finance(), want: false, wantWhy: SkipDestination},
		{name: "DLP Finanzas on snowflake", scope: dlpFinance, target: runQuery(), caller: finance(), want: true},
		{name: "Finanzas on jira", scope: dlpFinance, target: MCPTarget{RegistryID: jira, Tool: "create_issue"}, caller: finance(), want: false, wantWhy: SkipDestination},
		{name: "Marketing on snowflake", scope: dlpFinance, target: runQuery(), caller: marketing(), want: false, wantWhy: SkipPrincipal},
		{name: "everyone but Finanzas: Marketing", scope: onlyNotFinance, target: runQuery(), caller: marketing(), want: true},
		{name: "everyone but Finanzas: Finanzas", scope: onlyNotFinance, target: runQuery(), caller: finance(), want: false, wantWhy: SkipExcept},
		{name: "everyone but Finanzas: api key", scope: onlyNotFinance, target: runQuery(), caller: MCPCaller{}, want: true},
		{name: "destination checked before principal", scope: onlyNotFinance, target: MCPTarget{RegistryID: jira, Tool: "run_query"}, caller: finance(), want: false, wantWhy: SkipDestination},
		{name: "inert principal on the scoped destination", scope: dlpFinance, target: runQuery(), caller: MCPCaller{PrincipalInert: true}, want: true},
		{name: "inert principal does not soften the destination", scope: dlpFinance, target: MCPTarget{RegistryID: jira, Tool: "create_issue"}, caller: MCPCaller{PrincipalInert: true}, want: false, wantWhy: SkipDestination},
		{name: "empty scope stays a tombstone for an inert principal", scope: &MCPScope{}, target: runQuery(), caller: MCPCaller{PrincipalInert: true}, want: false, wantWhy: SkipDestination},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, why := tc.scope.Matches(tc.target, tc.caller)
			if got != tc.want || why != tc.wantWhy {
				t.Fatalf("Matches() = (%v, %q), want (%v, %q)", got, why, tc.want, tc.wantWhy)
			}
		})
	}
}

func TestMCPScope_Validate_Accepts(t *testing.T) {
	t.Parallel()
	var nilScope *MCPScope
	if err := nilScope.Validate(); err != nil {
		t.Fatalf("nil scope: unexpected error %v", err)
	}
	if err := (&MCPScope{}).Validate(); err != nil {
		t.Fatalf("empty scope: unexpected error %v", err)
	}
	full := &MCPScope{
		RegistryIDs:  []ids.RegistryID{jira},
		Tools:        []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}, {RegistryID: snowflake, Tool: "list_tables"}},
		Groups:       []string{"Finanzas"},
		ExceptGroups: []string{"Interns"},
	}
	if err := full.Validate(); err != nil {
		t.Fatalf("full scope: unexpected error %v", err)
	}
}

func TestMCPScope_Validate_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		scope *MCPScope
		want  string
	}{
		{name: "nil registry id", scope: &MCPScope{RegistryIDs: []ids.RegistryID{{}}}, want: "nil registry_id"},
		{name: "duplicate registry id", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake, snowflake}}, want: "duplicate registry_id"},
		{name: "nil registry in tools", scope: &MCPScope{Tools: []MCPToolRef{{Tool: "run_query"}}}, want: "nil registry_id in tools"},
		{name: "empty tool", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: ""}}}, want: "empty tool"},
		{name: "blank tool", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "   "}}}, want: "empty tool"},
		{name: "duplicate tool", scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}, {RegistryID: snowflake, Tool: " run_query "}}}, want: "duplicate tool"},
		{name: "registry in both lists", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}}, want: "both registry_ids and tools"},
		{name: "blank group", scope: &MCPScope{Groups: []string{" "}}, want: "empty entry in groups"},
		{name: "duplicate group", scope: &MCPScope{Groups: []string{"Finanzas", "Finanzas"}}, want: "duplicate entry \"Finanzas\" in groups"},
		{name: "empty except group", scope: &MCPScope{ExceptGroups: []string{""}}, want: "empty entry in except_groups"},
		{name: "duplicate except group", scope: &MCPScope{ExceptGroups: []string{"a", "a"}}, want: "in except_groups"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.scope.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidMCPScope) {
				t.Fatalf("err = %v, want wrap of ErrInvalidMCPScope", err)
			}
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want wrap of commonerrors.ErrValidation", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestMCPScope_Normalize(t *testing.T) {
	t.Parallel()
	var nilScope *MCPScope
	nilScope.Normalize()
	s := &MCPScope{
		Tools:        []MCPToolRef{{RegistryID: snowflake, Tool: " run_query "}},
		Groups:       []string{" Finanzas "},
		ExceptGroups: []string{" Interns"},
	}
	s.Normalize()
	if s.Tools[0].Tool != "run_query" {
		t.Fatalf("Tool = %q, want run_query", s.Tools[0].Tool)
	}
	if s.Groups[0] != "Finanzas" || s.ExceptGroups[0] != "Interns" {
		t.Fatalf("groups not trimmed: %v %v", s.Groups, s.ExceptGroups)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("normalized scope must validate: %v", err)
	}
}

func TestPolicy_PruneRegistry(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		scope       *MCPScope
		prune       ids.RegistryID
		wantChanged bool
		wantScope   *MCPScope
	}{
		{
			name:        "nil scope",
			scope:       nil,
			prune:       snowflake,
			wantChanged: false,
			wantScope:   nil,
		},
		{
			name:        "nil registry id",
			scope:       &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			prune:       ids.RegistryID{},
			wantChanged: false,
			wantScope:   &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
		},
		{
			name:        "unreferenced registry",
			scope:       &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			prune:       jira,
			wantChanged: false,
			wantScope:   &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
		},
		{
			name:        "several registries",
			scope:       &MCPScope{RegistryIDs: []ids.RegistryID{snowflake, jira}},
			prune:       jira,
			wantChanged: true,
			wantScope:   &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
		},
		{
			name:        "single registry in tools leaves {}",
			scope:       &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}},
			prune:       snowflake,
			wantChanged: true,
			wantScope:   &MCPScope{},
		},
		{
			name: "tool pruned keeps other registry tools",
			scope: &MCPScope{Tools: []MCPToolRef{
				{RegistryID: snowflake, Tool: "run_query"},
				{RegistryID: jira, Tool: "create_issue"},
			}},
			prune:       snowflake,
			wantChanged: true,
			wantScope:   &MCPScope{Tools: []MCPToolRef{{RegistryID: jira, Tool: "create_issue"}}},
		},
		{
			name:        "registry in both lists",
			scope:       &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}, {RegistryID: jira, Tool: "create_issue"}}},
			prune:       snowflake,
			wantChanged: true,
			wantScope:   &MCPScope{Tools: []MCPToolRef{{RegistryID: jira, Tool: "create_issue"}}},
		},
		{
			name:        "last destination drops principal too",
			scope:       &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Groups: []string{"Finanzas"}},
			prune:       snowflake,
			wantChanged: true,
			wantScope:   &MCPScope{},
		},
		{
			name:        "principal only scope is untouched",
			scope:       &MCPScope{Groups: []string{"Finanzas"}},
			prune:       snowflake,
			wantChanged: false,
			wantScope:   &MCPScope{Groups: []string{"Finanzas"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &Policy{MCPScope: tc.scope}
			if got := p.PruneRegistry(tc.prune); got != tc.wantChanged {
				t.Fatalf("PruneRegistry() = %v, want %v", got, tc.wantChanged)
			}
			got, _ := json.Marshal(p.MCPScope)
			want, _ := json.Marshal(tc.wantScope)
			if string(got) != string(want) {
				t.Fatalf("scope after prune = %s, want %s", got, want)
			}
			if tc.wantScope != nil && tc.wantScope.IsEmpty() {
				if p.MCPScope == nil {
					t.Fatal("pruned scope must be {} not nil")
				}
				if ok, _ := p.MCPScope.Matches(runQuery(), finance()); ok {
					t.Fatal("pruned {} scope must not match")
				}
			}
		})
	}
}

func TestPolicy_PruneRegistry_NilPolicy(t *testing.T) {
	t.Parallel()
	var p *Policy
	if p.PruneRegistry(snowflake) {
		t.Fatal("nil policy must report no change")
	}
}

func TestPolicy_MCPScope_JSON(t *testing.T) {
	t.Parallel()
	withoutScope, err := json.Marshal(&Policy{Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(withoutScope), "mcp_scope") {
		t.Fatalf("nil scope must be omitted: %s", withoutScope)
	}
	withEmpty, err := json.Marshal(&Policy{Name: "x", MCPScope: &MCPScope{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(withEmpty), `"mcp_scope":{}`) {
		t.Fatalf("empty scope must serialise as {}: %s", withEmpty)
	}
	full := &MCPScope{
		RegistryIDs:  []ids.RegistryID{jira},
		Tools:        []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}},
		Groups:       []string{"Finanzas"},
		ExceptGroups: []string{"Interns"},
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"registry_ids"`, `"tools"`, `"registry_id"`, `"tool"`, `"groups"`, `"except_groups"`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("json %s lacks %s", raw, key)
		}
	}
	for _, key := range []string{`"users"`, `"except_users"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("json %s still carries the retired %s", raw, key)
		}
	}
	var back MCPScope
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if ok, _ := back.Matches(runQuery(), finance()); !ok {
		t.Fatal("round-tripped scope must still match")
	}
}

// TestMCPScopeUnmarshalDropsRetiredUsers pins what a row written before the
// user dimension was removed decodes to. Dropping the keys here is what makes
// migration 20260917120000 necessary: a scope that named only users decodes to
// {} and goes dormant, but one that also named a destination would otherwise
// keep it and widen to every caller of it.
func TestMCPScopeUnmarshalDropsRetiredUsers(t *testing.T) {
	t.Parallel()
	var usersOnly MCPScope
	if err := json.Unmarshal([]byte(`{"users":["ana@acme.com"],"except_users":["bob@acme.com"]}`), &usersOnly); err != nil {
		t.Fatal(err)
	}
	if !usersOnly.IsEmpty() {
		t.Fatalf("scope = %+v, want the empty scope that matches nothing", usersOnly)
	}
	var withDestination MCPScope
	if err := json.Unmarshal(
		[]byte(`{"registry_ids":["`+snowflake.String()+`"],"users":["ana@acme.com"]}`), &withDestination,
	); err != nil {
		t.Fatal(err)
	}
	if withDestination.HasPrincipal() {
		t.Fatal("the user dimension must not survive the decode")
	}
	if ok, _ := withDestination.Matches(runQuery(), MCPCaller{}); !ok {
		t.Fatal("a destination-only scope applies to every caller, which is why the rows are migrated")
	}
}

func TestMCPScope_CrossesPlanes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		scope *MCPScope
		want  bool
	}{
		{name: "nil scope gates nothing and runs everywhere", scope: nil, want: false},
		{name: "tombstone runs nowhere", scope: &MCPScope{}, want: false},
		{name: "groups only", scope: &MCPScope{Groups: []string{"Finanzas"}}, want: true},
		{name: "except_groups only", scope: &MCPScope{ExceptGroups: []string{"Finanzas"}}, want: true},
		{name: "registry destination", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}, want: false},
		{
			name:  "groups and registry destination",
			scope: &MCPScope{Groups: []string{"Finanzas"}, RegistryIDs: []ids.RegistryID{snowflake}},
			want:  false,
		},
		{
			name:  "tool destination",
			scope: &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}},
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.CrossesPlanes(); got != tc.want {
				t.Fatalf("CrossesPlanes() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestMCPScope_Dormant(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		scope *MCPScope
		want  bool
	}{
		{name: "nil", scope: nil, want: false},
		{name: "present and naming nothing", scope: &MCPScope{}, want: true},
		{name: "principal entry", scope: &MCPScope{Groups: []string{"Finanzas"}}, want: false},
		{name: "destination entry", scope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.Dormant(); got != tc.want {
				t.Fatalf("Dormant() = %t, want %t", got, tc.want)
			}
		})
	}
}
