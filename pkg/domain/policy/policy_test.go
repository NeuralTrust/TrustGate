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
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestPolicy_New_HappyPath(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p, err := NewPolicy(gwID, "default", "rate_limiter", true, 10, false,
		map[string]any{"limit": 100}, []Stage{StagePreRequest}, "my description", ModeEnforce, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ID.IsNil() {
		t.Fatal("ID is zero")
	}
	if p.GatewayID != gwID {
		t.Fatalf("GatewayID = %s, want %s", p.GatewayID, gwID)
	}
	if p.Slug != "rate_limiter" {
		t.Fatalf("Slug = %s, want rate_limiter", p.Slug)
	}
	if p.Description != "my description" {
		t.Fatalf("Description = %q, want %q", p.Description, "my description")
	}
	if !p.Enabled || p.Priority != 10 {
		t.Fatalf("unexpected enabled/priority: %+v", p)
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Fatal("timestamps are zero")
	}
}

func TestPolicy_New_AllowsEmptyStages(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(ids.New[ids.GatewayKind](), "no-stages", "cors", true, 0, false, nil, nil, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Stages) != 0 {
		t.Fatalf("Stages len = %d, want 0", len(p.Stages))
	}
	if p.Mode != ModeEnforce {
		t.Fatalf("Mode = %q, want default %q", p.Mode, ModeEnforce)
	}
}

func TestPolicy_Validate_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Policy)
		wantErr error
	}{
		{
			name:    "empty name",
			mutate:  func(p *Policy) { p.Name = "" },
			wantErr: ErrInvalidName,
		},
		{
			name:    "empty slug",
			mutate:  func(p *Policy) { p.Slug = "" },
			wantErr: ErrInvalidSlug,
		},
		{
			name:    "nil gateway id",
			mutate:  func(p *Policy) { p.GatewayID = ids.GatewayID{} },
			wantErr: ErrInvalidGatewayID,
		},
		{
			name:    "unknown stage",
			mutate:  func(p *Policy) { p.Stages = []Stage{Stage("bogus")} },
			wantErr: ErrInvalidStage,
		},
		{
			name:    "unknown mode",
			mutate:  func(p *Policy) { p.Mode = Mode("bogus") },
			wantErr: ErrInvalidMode,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &Policy{
				ID:        ids.New[ids.PolicyKind](),
				GatewayID: ids.New[ids.GatewayKind](),
				Name:      "x",
				Slug:      "rate_limiter",
			}
			tc.mutate(p)
			err := p.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want wrap of %v", err, tc.wantErr)
			}
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want wrap of commonerrors.ErrValidation", err)
			}
		})
	}
}

func TestPolicy_Validate_AcceptsAllKnownStages(t *testing.T) {
	t.Parallel()
	p := &Policy{
		ID:        ids.New[ids.PolicyKind](),
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "all-stages",
		Slug:      "x",
		Stages: []Stage{
			StagePreRequest,
			StagePostRequest,
			StagePreResponse,
			StagePostResponse,
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicy_Rehydrate(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.PolicyKind]()
	gwID := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	p := Rehydrate(id, gwID, nil, "x", "rehydrated description", "cors", true, true, 5, true,
		map[string]any{"k": "v"}, []Stage{StagePreRequest}, ModeEnforce, nil, now, now)
	if p.ID != id || p.GatewayID != gwID {
		t.Fatal("identity mismatch after rehydrate")
	}
	if p.Slug != "cors" || !p.Enabled || !p.Global || p.Priority != 5 || !p.Parallel {
		t.Fatalf("unexpected fields after rehydrate: %+v", p)
	}
	if p.Description != "rehydrated description" {
		t.Fatalf("Description = %q, want %q", p.Description, "rehydrated description")
	}
	if !p.CreatedAt.Equal(now) {
		t.Fatal("CreatedAt mismatch")
	}
}

func TestPolicy_New_WithMCPScope(t *testing.T) {
	t.Parallel()
	scope := &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Groups: []string{"Finanzas"}}
	p, err := NewPolicy(ids.New[ids.GatewayKind](), "dlp", "trustguard", true, 0, false, nil, nil, "", ModeEnforce, scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.MCPScope != scope {
		t.Fatalf("MCPScope = %+v, want the scope passed in", p.MCPScope)
	}
	invalid := &MCPScope{RegistryIDs: []ids.RegistryID{snowflake}, Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}}
	if _, err := NewPolicy(ids.New[ids.GatewayKind](), "dlp", "trustguard", true, 0, false, nil, nil, "", ModeEnforce, invalid); !errors.Is(err, ErrInvalidMCPScope) {
		t.Fatalf("err = %v, want wrap of ErrInvalidMCPScope", err)
	}
}

func TestPolicy_Validate_DelegatesToMCPScope(t *testing.T) {
	t.Parallel()
	p := &Policy{
		ID:        ids.New[ids.PolicyKind](),
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "x",
		Slug:      "trustguard",
		MCPScope:  &MCPScope{Groups: []string{""}},
	}
	err := p.Validate()
	if !errors.Is(err, ErrInvalidMCPScope) || !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want wrap of ErrInvalidMCPScope and ErrValidation", err)
	}
	p.MCPScope = &MCPScope{}
	if err := p.Validate(); err != nil {
		t.Fatalf("a pruned {} scope must validate: %v", err)
	}
}

func TestPolicy_Rehydrate_KeepsMCPScope(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	scope := &MCPScope{Tools: []MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}}
	p := Rehydrate(ids.New[ids.PolicyKind](), ids.New[ids.GatewayKind](), nil, "x", "", "cors", true, false, 0, false,
		nil, nil, ModeEnforce, scope, now, now)
	if p.MCPScope != scope {
		t.Fatalf("MCPScope = %+v, want the scope passed in", p.MCPScope)
	}
}

func TestPolicy_Dormant(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		policy *Policy
		want   bool
	}{
		{name: "nil policy", policy: nil, want: false},
		{name: "no scope", policy: &Policy{}, want: false},
		{name: "tombstone scope", policy: &Policy{MCPScope: &MCPScope{}}, want: true},
		{name: "scope with entries", policy: &Policy{MCPScope: &MCPScope{Groups: []string{"Finanzas"}}}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.policy.Dormant(); got != tc.want {
				t.Fatalf("Dormant() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestPolicy_IsGlobal_ReadsOnlyTheGlobalFlag(t *testing.T) {
	t.Parallel()
	attached := &Policy{Global: false, ConsumerIDs: []ids.ConsumerID{ids.New[ids.ConsumerKind]()}}
	if attached.IsGlobal() {
		t.Fatal("a policy attached to consumers must not become global")
	}
	global := &Policy{Global: true, ConsumerIDs: []ids.ConsumerID{ids.New[ids.ConsumerKind]()}}
	if !global.IsGlobal() {
		t.Fatal("IsGlobal must report the Global flag, not the absence of consumers")
	}
	bare := &Policy{Global: true}
	if !bare.IsGlobal() {
		t.Fatal("IsGlobal must report the Global flag for a policy with no consumers")
	}
	dormant := &Policy{Global: true, MCPScope: &MCPScope{}}
	if !dormant.IsGlobal() {
		t.Fatal("a tombstone scope must not change what IsGlobal reports")
	}
}
