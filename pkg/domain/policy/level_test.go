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
	"errors"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

var (
	consumerX = ids.New[ids.ConsumerKind]()
	consumerY = ids.New[ids.ConsumerKind]()
	warehouse = ids.New[ids.RegistryKind]()
)

func TestMCPScope_Occupancy_CartesianProduct(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		scope     *MCPScope
		consumers []ids.ConsumerID
		want      int
	}{
		{
			name: "nil scope and no consumers is the all traffic level",
			want: 1,
		},
		{
			name:      "nil scope takes one level per consumer",
			consumers: []ids.ConsumerID{consumerX, consumerY},
			want:      2,
		},
		{
			name:  "tombstone takes no level",
			scope: &MCPScope{},
			want:  0,
		},
		{
			name:      "tombstone takes no level however many consumers it names",
			scope:     &MCPScope{},
			consumers: []ids.ConsumerID{consumerX, consumerY},
			want:      0,
		},
		{
			name: "two consumers by two registries by one group is four levels",
			scope: &MCPScope{
				RegistryIDs: []ids.RegistryID{snowflake, jira},
				Groups:      []string{"Finanzas"},
			},
			consumers: []ids.ConsumerID{consumerX, consumerY},
			want:      4,
		},
		{
			name: "registries and tools are ranges of one destination dimension",
			scope: &MCPScope{
				RegistryIDs: []ids.RegistryID{snowflake},
				Tools:       []MCPToolRef{{RegistryID: jira, Tool: "create_issue"}},
			},
			want: 2,
		},
		{
			name: "except_groups alone leaves the group dimension open",
			scope: &MCPScope{
				ExceptGroups: []string{"Finanzas"},
			},
			consumers: []ids.ConsumerID{consumerX},
			want:      1,
		},
		{
			name: "duplicate group entries collapse into one level",
			scope: &MCPScope{
				Groups: []string{"Finanzas", " Finanzas "},
			},
			want: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.scope.Occupancy(tc.consumers).Len(); got != tc.want {
				t.Fatalf("Occupancy() holds %d levels, want %d", got, tc.want)
			}
		})
	}
}

func TestMCPScope_Occupancy_NamesEveryCombination(t *testing.T) {
	t.Parallel()
	scope := &MCPScope{
		RegistryIDs: []ids.RegistryID{snowflake, jira},
		Groups:      []string{"Finanzas"},
	}
	got := scope.Occupancy([]ids.ConsumerID{consumerX, consumerY})
	for _, consumer := range []ids.ConsumerID{consumerX, consumerY} {
		for _, registry := range []ids.RegistryID{snowflake, jira} {
			want := AllTraffic().WithConsumer(consumer).WithGroup("Finanzas").WithRegistry(registry)
			if !got.Has(want) {
				t.Fatalf("Occupancy() is missing level %s", want)
			}
		}
	}
}

func TestOverlaps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		a, b      *MCPScope
		consumers []ids.ConsumerID
		otherCons []ids.ConsumerID
		want      bool
	}{
		{
			name:      "partial overlap on registries: [a,b] against [b,c]",
			a:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake, jira}},
			b:         &MCPScope{RegistryIDs: []ids.RegistryID{jira, warehouse}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      true,
		},
		{
			name:      "partial overlap on consumers",
			a:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			b:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			consumers: []ids.ConsumerID{consumerX, consumerY},
			otherCons: []ids.ConsumerID{consumerY},
			want:      true,
		},
		{
			name:      "partial overlap on groups",
			a:         &MCPScope{Groups: []string{"Finanzas", "Ingenieria"}},
			b:         &MCPScope{Groups: []string{"Ingenieria", "Marketing"}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      true,
		},
		{
			name:      "exact equality overlaps",
			a:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Groups: []string{"Finanzas"}},
			b:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Groups: []string{"Finanzas"}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      true,
		},
		{
			name:      "same consumer and different groups are different levels",
			a:         &MCPScope{Groups: []string{"Finanzas"}},
			b:         &MCPScope{Groups: []string{"Ingenieria"}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      false,
		},
		{
			name:      "same scope on different consumers are different levels",
			a:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			b:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerY},
			want:      false,
		},
		{
			name:      "disjoint registries are different levels",
			a:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			b:         &MCPScope{RegistryIDs: []ids.RegistryID{jira}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      false,
		},
		{
			name:      "except_groups does not break the tie",
			a:         &MCPScope{Groups: []string{"Finanzas"}, ExceptGroups: []string{"Becarios"}},
			b:         &MCPScope{Groups: []string{"Finanzas"}, ExceptGroups: []string{"Contratistas"}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      true,
		},
		{
			name:      "a tombstone takes no level and clashes with nothing",
			a:         &MCPScope{},
			b:         nil,
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      false,
		},
		{
			name:      "two tombstones do not clash with each other",
			a:         &MCPScope{},
			b:         &MCPScope{},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      false,
		},
		{
			name:      "all traffic clashes with all traffic",
			consumers: nil,
			otherCons: nil,
			want:      true,
		},
		{
			name:      "all traffic is a level of its own, not a wildcard over consumers",
			consumers: nil,
			otherCons: []ids.ConsumerID{consumerX},
			want:      false,
		},
		{
			name:      "a whole registry and one of its tools are different levels",
			a:         &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			b:         &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      false,
		},
		{
			name:      "the same tool of the same registry is one level",
			a:         &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}},
			b:         &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}, {RegistryID: jira, Tool: "create_issue"}}},
			consumers: []ids.ConsumerID{consumerX},
			otherCons: []ids.ConsumerID{consumerX},
			want:      true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := tc.a.Occupancy(tc.consumers)
			b := tc.b.Occupancy(tc.otherCons)
			if got := Overlaps(a, b); got != tc.want {
				t.Fatalf("Overlaps() = %t, want %t", got, tc.want)
			}
			if got := Overlaps(b, a); got != tc.want {
				t.Fatalf("Overlaps() is not symmetric: reversed = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestFirstOverlap_NamesTheSharedLevel(t *testing.T) {
	t.Parallel()
	a := (&MCPScope{RegistryIDs: []ids.RegistryID{snowflake, jira}}).Occupancy([]ids.ConsumerID{consumerX})
	b := (&MCPScope{RegistryIDs: []ids.RegistryID{jira, warehouse}}).Occupancy([]ids.ConsumerID{consumerX})
	got, ok := FirstOverlap(a, b)
	if !ok {
		t.Fatal("FirstOverlap() found nothing, want the level of the shared registry")
	}
	want := AllTraffic().WithConsumer(consumerX).WithRegistry(jira)
	if got != want {
		t.Fatalf("FirstOverlap() = %s, want %s", got, want)
	}
	if _, ok := FirstOverlap(a, make(OccupancySet)); ok {
		t.Fatal("FirstOverlap() against an empty set must find nothing")
	}
}

func TestPolicy_Occupancy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		policy *Policy
		want   int
	}{
		{
			name:   "nil policy takes no level",
			policy: nil,
			want:   0,
		},
		{
			name: "a disabled policy takes no level",
			policy: &Policy{
				Enabled:     false,
				ConsumerIDs: []ids.ConsumerID{consumerX, consumerY},
				MCPScope:    &MCPScope{RegistryIDs: []ids.RegistryID{snowflake, jira}},
			},
			want: 0,
		},
		{
			name: "the same policy enabled takes the whole product",
			policy: &Policy{
				Enabled:     true,
				ConsumerIDs: []ids.ConsumerID{consumerX, consumerY},
				MCPScope:    &MCPScope{RegistryIDs: []ids.RegistryID{snowflake, jira}},
			},
			want: 4,
		},
		{
			name: "a tombstone takes no level even when enabled",
			policy: &Policy{
				Enabled:     true,
				ConsumerIDs: []ids.ConsumerID{consumerX},
				MCPScope:    &MCPScope{},
			},
			want: 0,
		},
		{
			// A draft: not global and nothing attached, so loadPolicies files it
			// under neither bucket and it runs nowhere. Occupying the wildcard
			// level here would make duplication always conflict, because a copy
			// is born in exactly this shape.
			name: "a draft takes no level",
			policy: &Policy{
				Enabled: true,
			},
			want: 0,
		},
		{
			name: "a draft with a scope still takes no level",
			policy: &Policy{
				Enabled:  true,
				MCPScope: &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}},
			},
			want: 0,
		},
		{
			name: "attaching one consumer is what makes a draft occupy",
			policy: &Policy{
				Enabled:     true,
				ConsumerIDs: []ids.ConsumerID{consumerX},
			},
			want: 1,
		},
		{
			name: "promoting a draft to global is the other way it starts occupying",
			policy: &Policy{
				Enabled: true,
				Global:  true,
			},
			want: 1,
		},
		{
			name: "a global policy runs for every consumer, so it drops its attachments",
			policy: &Policy{
				Enabled:     true,
				Global:      true,
				ConsumerIDs: []ids.ConsumerID{consumerX, consumerY},
			},
			want: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.policy.Occupancy().Len(); got != tc.want {
				t.Fatalf("Occupancy() holds %d levels, want %d", got, tc.want)
			}
		})
	}
}

func TestPolicy_Occupancy_GlobalTakesTheAllTrafficLevel(t *testing.T) {
	t.Parallel()
	global := &Policy{Enabled: true, Global: true, ConsumerIDs: []ids.ConsumerID{consumerX}}
	if !global.Occupancy().Has(AllTraffic()) {
		t.Fatal("a global policy must take the all traffic level")
	}
	attached := &Policy{Enabled: true, ConsumerIDs: []ids.ConsumerID{consumerX}}
	if Overlaps(global.Occupancy(), attached.Occupancy()) {
		t.Fatal("all traffic and one consumer are different levels")
	}
}

func TestLevel_WildcardIsNotTheZeroUUID(t *testing.T) {
	t.Parallel()
	var nilConsumer ids.ConsumerID
	if !nilConsumer.IsNil() {
		t.Fatal("the zero ConsumerID must be the nil uuid")
	}
	all := AllTraffic()
	zero := AllTraffic().WithConsumer(nilConsumer)
	if all == zero {
		t.Fatal("the consumer wildcard and a nil consumer id must be different levels")
	}
	if _, ok := all.Consumer(); ok {
		t.Fatal("the all traffic level must report no consumer")
	}
	got, ok := zero.Consumer()
	if !ok || !got.IsNil() {
		t.Fatalf("Consumer() = %s, %t, want the nil uuid reported as present", got, ok)
	}
	empty := AllTraffic().WithGroup("")
	if empty == all {
		t.Fatal("the group wildcard and an empty group must be different levels")
	}
}

func TestLevel_Accessors(t *testing.T) {
	t.Parallel()
	registry := AllTraffic().WithRegistry(snowflake)
	ref, ok := registry.Destination()
	if !ok || ref.RegistryID != snowflake || ref.Tool != "" {
		t.Fatalf("Destination() = %+v, %t, want the whole registry", ref, ok)
	}
	tool := AllTraffic().WithTool(MCPToolRef{RegistryID: snowflake, Tool: "run_query"})
	ref, ok = tool.Destination()
	if !ok || ref.RegistryID != snowflake || ref.Tool != "run_query" {
		t.Fatalf("Destination() = %+v, %t, want the single tool", ref, ok)
	}
	if _, ok := AllTraffic().Destination(); ok {
		t.Fatal("the all traffic level must report no destination")
	}
	group, ok := AllTraffic().WithGroup("Finanzas").Group()
	if !ok || group != "Finanzas" {
		t.Fatalf("Group() = %q, %t, want Finanzas", group, ok)
	}
	if _, ok := AllTraffic().Group(); ok {
		t.Fatal("the all traffic level must report no group")
	}
}

func TestLevel_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		level Level
		want  string
	}{
		{
			name:  "all traffic",
			level: AllTraffic(),
			want:  "consumer=all group=all resource=all",
		},
		{
			name:  "consumer and group",
			level: AllTraffic().WithConsumer(consumerX).WithGroup("Finanzas"),
			want:  "consumer=" + consumerX.String() + " group=Finanzas resource=all",
		},
		{
			name:  "whole registry",
			level: AllTraffic().WithRegistry(snowflake),
			want:  "consumer=all group=all resource=" + snowflake.String(),
		},
		{
			name:  "single tool",
			level: AllTraffic().WithTool(MCPToolRef{RegistryID: snowflake, Tool: "run_query"}),
			want:  "consumer=all group=all resource=" + snowflake.String() + "/run_query",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.level.String(); got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOccupancySet_LevelsIsOrdered(t *testing.T) {
	t.Parallel()
	scope := &MCPScope{RegistryIDs: []ids.RegistryID{snowflake, jira, warehouse}}
	levels := scope.Occupancy([]ids.ConsumerID{consumerX, consumerY}).Levels()
	if len(levels) != 6 {
		t.Fatalf("Levels() returned %d levels, want 6", len(levels))
	}
	for i := 1; i < len(levels); i++ {
		if levels[i-1].String() >= levels[i].String() {
			t.Fatalf("Levels() is not ordered at %d: %s then %s", i, levels[i-1], levels[i])
		}
	}
}

func TestLevelConflict(t *testing.T) {
	t.Parallel()
	occupant := &Policy{
		ID:   ids.New[ids.PolicyKind](),
		Name: "TrustGuard estricto",
		Slug: "trustguard",
	}
	level := AllTraffic().WithConsumer(consumerX).WithGroup("Finanzas")
	err := LevelConflict(occupant, level)
	if !errors.Is(err, ErrPolicyLevelConflict) {
		t.Fatalf("err = %v, want ErrPolicyLevelConflict", err)
	}
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want it to wrap ErrConflict so the edge answers 409", err)
	}
	for _, want := range []string{
		occupant.ID.String(),
		`"TrustGuard estricto"`,
		"trustguard",
		level.String(),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %q, want it to name %q", err, want)
		}
	}
	if !errors.Is(LevelConflict(nil, level), commonerrors.ErrConflict) {
		t.Fatal("LevelConflict(nil, ...) must still be a conflict")
	}
}
