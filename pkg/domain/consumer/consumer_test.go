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
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func validParams() CreateParams {
	return CreateParams{
		GatewayID:   ids.New[ids.GatewayKind](),
		Name:        "openai-chat",
		Type:        TypeLLM,
		RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()},
	}
}

func TestNewRoutingMode_Normalizes(t *testing.T) {
	t.Parallel()
	cases := map[string]RoutingMode{
		"inline":       RoutingModeInline,
		"  inline  ":   RoutingModeInline,
		"INLINE":       RoutingModeInline,
		"Role_Based":   RoutingModeRoleBased,
		" role_based ": RoutingModeRoleBased,
		"":             RoutingMode(""),
	}
	for raw, want := range cases {
		if got := NewRoutingMode(raw); got != want {
			t.Errorf("NewRoutingMode(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestConsumer_New_HappyPath(t *testing.T) {
	t.Parallel()
	p := validParams()
	c, err := New(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ID.IsNil() {
		t.Fatal("ID is zero")
	}
	if c.GatewayID != p.GatewayID {
		t.Fatalf("GatewayID = %s, want %s", c.GatewayID, p.GatewayID)
	}
	if c.Type != TypeLLM {
		t.Fatalf("Type = %q, want %q", c.Type, TypeLLM)
	}
	if c.RoutingMode != RoutingModeInline {
		t.Fatalf("RoutingMode = %q, want %q", c.RoutingMode, RoutingModeInline)
	}
	if !c.Active {
		t.Fatal("Active should default to true")
	}
	if c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() {
		t.Fatal("timestamps are zero")
	}
	if !IsValidSlug(c.Slug) {
		t.Fatalf("Slug = %q, want a valid generated slug", c.Slug)
	}
}

func TestConsumer_New_TypeDefaultsToLLM(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.Type = ""
	c, err := New(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Type != TypeLLM {
		t.Fatalf("Type = %q, want %q", c.Type, TypeLLM)
	}
}

func TestConsumer_New_RespectsActiveOverride(t *testing.T) {
	t.Parallel()
	p := validParams()
	off := false
	p.Active = &off
	c, err := New(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Active {
		t.Fatal("Active should be false when overridden")
	}
}

func TestConsumer_Validate_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Consumer)
		wantErr error
	}{
		{
			name:    "empty name",
			mutate:  func(c *Consumer) { c.Name = "" },
			wantErr: ErrInvalidName,
		},
		{
			name:    "nil gateway id",
			mutate:  func(c *Consumer) { c.GatewayID = ids.GatewayID{} },
			wantErr: ErrInvalidGatewayID,
		},
		{
			name:    "unknown type",
			mutate:  func(c *Consumer) { c.Type = "WUT" },
			wantErr: ErrInvalidType,
		},
		{
			name:    "empty slug",
			mutate:  func(c *Consumer) { c.Slug = "" },
			wantErr: ErrInvalidSlug,
		},
		{
			name:    "malformed slug",
			mutate:  func(c *Consumer) { c.Slug = "bad/slug" },
			wantErr: ErrInvalidSlug,
		},
		{
			name:    "invalid routing mode",
			mutate:  func(c *Consumer) { c.RoutingMode = "mixed" },
			wantErr: ErrInvalidRoutingMode,
		},
		{
			name: "role based rejects inline registries",
			mutate: func(c *Consumer) {
				c.RoutingMode = RoutingModeRoleBased
			},
			wantErr: ErrInvalidRoutingMode,
		},
		{
			name:    "mcp policy on llm consumer",
			mutate:  func(c *Consumer) { c.MCP = &MCPPolicy{} },
			wantErr: ErrInvalidType,
		},
		{
			name: "role based rejects mcp policy",
			mutate: func(c *Consumer) {
				c.Type = TypeMCP
				c.RoutingMode = RoutingModeRoleBased
				c.RegistryIDs = nil
				c.MCP = &MCPPolicy{}
			},
			wantErr: ErrInvalidRoutingMode,
		},
		{
			name: "duplicate backend",
			mutate: func(c *Consumer) {
				id := ids.New[ids.RegistryKind]()
				c.RegistryIDs = []ids.RegistryID{id, id}
			},
			wantErr: ErrInvalidModelPolicy,
		},
		{
			name:    "nil backend uuid",
			mutate:  func(c *Consumer) { c.RegistryIDs = []ids.RegistryID{{}} },
			wantErr: ErrInvalidModelPolicy,
		},
		{
			name: "role based rejects lb config",
			mutate: func(c *Consumer) {
				c.RoutingMode = RoutingModeRoleBased
				c.RegistryIDs = nil
				c.LBConfig = &LBConfig{}
			},
			wantErr: ErrInvalidRoutingMode,
		},
		{
			name: "role based rejects enabled fallback",
			mutate: func(c *Consumer) {
				c.RoutingMode = RoutingModeRoleBased
				c.RegistryIDs = nil
				c.Fallback = &Fallback{Enabled: true}
			},
			wantErr: ErrInvalidRoutingMode,
		},
		{
			name: "role based rejects model policies",
			mutate: func(c *Consumer) {
				c.RoutingMode = RoutingModeRoleBased
				c.RegistryIDs = nil
				c.ModelPolicies = ModelPolicies{ids.New[ids.RegistryKind](): {}}
			},
			wantErr: ErrInvalidRoutingMode,
		},
		{
			name: "inline rejects roles",
			mutate: func(c *Consumer) {
				c.RoleIDs = []ids.RoleID{ids.New[ids.RoleKind]()}
			},
			wantErr: ErrInvalidRoutingMode,
		},
		{
			name: "role based rejects duplicate roles",
			mutate: func(c *Consumer) {
				c.RoutingMode = RoutingModeRoleBased
				c.RegistryIDs = nil
				id := ids.New[ids.RoleKind]()
				c.RoleIDs = []ids.RoleID{id, id}
			},
			wantErr: ErrInvalidRoutingMode,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Consumer{
				ID:          ids.New[ids.ConsumerKind](),
				GatewayID:   ids.New[ids.GatewayKind](),
				Name:        "x",
				Type:        TypeLLM,
				Slug:        "X84Yhsy8",
				RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()},
			}
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want wrap of %v", err, tc.wantErr)
			}
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("err = %v, want it to wrap commonerrors.ErrValidation", err)
			}
		})
	}
}

func TestConsumer_New_AllowsZeroRegistries(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.RegistryIDs = nil
	c, err := New(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.RegistryIDs) != 0 {
		t.Fatalf("RegistryIDs = %v, want empty", c.RegistryIDs)
	}
}

func TestConsumer_Rehydrate(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	now := time.Now().UTC()
	toolkit := Toolkit{{RegistryID: beID, Tool: "search", ExposeAs: "gh_search"}}
	c := Rehydrate(RehydrateParams{
		ID:          id,
		GatewayID:   gwID,
		Name:        "x",
		Type:        TypeMCP,
		Slug:        "X84Yhsy8",
		RoutingMode: RoutingModeInline,
		Headers:     map[string]string{"X-K": "v"},
		Active:      true,
		RegistryIDs: []ids.RegistryID{beID},
		MCP:         &MCPPolicy{Toolkit: toolkit, FailMode: FailModeOpen},
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if c.ID != id || c.GatewayID != gwID {
		t.Fatal("identity mismatch after rehydrate")
	}
	if c.Type != TypeMCP {
		t.Fatalf("Type = %q", c.Type)
	}
	if c.Slug != "X84Yhsy8" {
		t.Fatalf("Slug = %q", c.Slug)
	}
	if !c.CreatedAt.Equal(now) {
		t.Fatal("CreatedAt mismatch")
	}
	if tk := c.Toolkit(); len(tk) != 1 || tk[0].Tool != "search" || tk[0].ExposeAs != "gh_search" {
		t.Fatalf("Toolkit lost on rehydrate: %+v", c.Toolkit())
	}
	if c.FailMode() != FailModeOpen {
		t.Fatalf("FailMode = %q, want %q", c.FailMode(), FailModeOpen)
	}
}

func TestType_Helpers(t *testing.T) {
	t.Parallel()
	for _, ty := range Types() {
		if !IsValidType(ty) {
			t.Fatalf("%q expected valid", ty)
		}
	}
	if IsValidType("rubbish") {
		t.Fatal("rubbish should be invalid")
	}
}
