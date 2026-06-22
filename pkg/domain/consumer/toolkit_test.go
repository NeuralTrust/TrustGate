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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestToolkit_Validate(t *testing.T) {
	t.Parallel()
	regA := ids.New[ids.RegistryKind]()
	regB := ids.New[ids.RegistryKind]()
	known := map[ids.RegistryID]struct{}{regA: {}, regB: {}}

	t.Run("valid toolkit", func(t *testing.T) {
		t.Parallel()
		tk := Toolkit{
			{RegistryID: regA, Tool: ToolWildcard},
			{RegistryID: regB, Tool: "create_issue", ExposeAs: "gh_create_issue"},
			{RegistryID: regB, Tool: "list_repos"},
			{RegistryID: regA, Prompt: "summarize", ExposeAs: "gh_summarize"},
			{RegistryID: regB, Prompt: ToolWildcard},
			{RegistryID: regA, Resource: "repo://github/*"},
			{RegistryID: regB, Resource: ToolWildcard},
		}
		if err := tk.Validate(known); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	tests := []struct {
		name string
		tk   Toolkit
	}{
		{"nil registry id", Toolkit{{Tool: "x"}}},
		{"unattached registry", Toolkit{{RegistryID: ids.New[ids.RegistryKind](), Tool: "x"}}},
		{"empty tool", Toolkit{{RegistryID: regA, Tool: " "}}},
		{"no selector", Toolkit{{RegistryID: regA}}},
		{"two selectors", Toolkit{{RegistryID: regA, Tool: "x", Prompt: "y"}}},
		{"duplicate tool", Toolkit{{RegistryID: regA, Tool: "x"}, {RegistryID: regA, Tool: "x"}}},
		{"duplicate prompt", Toolkit{{RegistryID: regA, Prompt: "x"}, {RegistryID: regA, Prompt: "x"}}},
		{"duplicate resource", Toolkit{{RegistryID: regA, Resource: "a://b"}, {RegistryID: regA, Resource: "a://b"}}},
		{"expose_as on wildcard", Toolkit{{RegistryID: regA, Tool: ToolWildcard, ExposeAs: "y"}}},
		{"expose_as on prompt wildcard", Toolkit{{RegistryID: regA, Prompt: ToolWildcard, ExposeAs: "y"}}},
		{"expose_as on resource", Toolkit{{RegistryID: regA, Resource: "a://b", ExposeAs: "y"}}},
		{"duplicate alias", Toolkit{
			{RegistryID: regA, Tool: "x", ExposeAs: "same"},
			{RegistryID: regB, Tool: "y", ExposeAs: "same"},
		}},
		{"duplicate alias across surfaces", Toolkit{
			{RegistryID: regA, Tool: "x", ExposeAs: "same"},
			{RegistryID: regA, Prompt: "y", ExposeAs: "same"},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.tk.Validate(known); !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("error = %v, want validation error", err)
			}
		})
	}
}

func TestToolkit_AllowsResource(t *testing.T) {
	t.Parallel()
	regA := ids.New[ids.RegistryKind]()
	regB := ids.New[ids.RegistryKind]()
	tk := Toolkit{
		{RegistryID: regA, Resource: "repo://github/*"},
		{RegistryID: regA, Resource: "docs://readme"},
		{RegistryID: regB, Tool: ToolWildcard},
	}

	tests := []struct {
		name string
		reg  ids.RegistryID
		uri  string
		want bool
	}{
		{"prefix match", regA, "repo://github/neuraltrust/trustgate", true},
		{"exact match", regA, "docs://readme", true},
		{"prefix mismatch", regA, "repo://gitlab/x", false},
		{"no resource entries for registry", regB, "repo://github/x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tk.AllowsResource(tc.reg, tc.uri); got != tc.want {
				t.Fatalf("AllowsResource(%s) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}

	t.Run("nil toolkit allows everything", func(t *testing.T) {
		t.Parallel()
		if !(Toolkit(nil)).AllowsResource(regA, "anything://x") {
			t.Fatal("nil toolkit must allow every resource")
		}
	})

	t.Run("empty toolkit denies everything", func(t *testing.T) {
		t.Parallel()
		if (Toolkit{}).AllowsResource(regA, "anything://x") {
			t.Fatal("a present-but-empty toolkit must deny every resource")
		}
	})
}

func TestConsumer_Validate_ToolkitAndFailMode(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	regID := ids.New[ids.RegistryKind]()

	t.Run("toolkit requires MCP type", func(t *testing.T) {
		t.Parallel()
		_, err := New(CreateParams{
			GatewayID:   gwID,
			Name:        "llm-consumer",
			Type:        TypeLLM,
			RegistryIDs: []ids.RegistryID{regID},
			MCP:         &MCPPolicy{Toolkit: Toolkit{{RegistryID: regID, Tool: ToolWildcard}}},
		})
		if !errors.Is(err, ErrInvalidType) {
			t.Fatalf("error = %v, want ErrInvalidType", err)
		}
	})

	t.Run("MCP consumer with toolkit", func(t *testing.T) {
		t.Parallel()
		c, err := New(CreateParams{
			GatewayID:   gwID,
			Name:        "mcp-consumer",
			Type:        TypeMCP,
			RegistryIDs: []ids.RegistryID{regID},
			MCP:         &MCPPolicy{Toolkit: Toolkit{{RegistryID: regID, Tool: ToolWildcard}}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.FailMode() != FailModeClosed {
			t.Fatalf("FailMode = %q, want default closed", c.FailMode())
		}
	})

	t.Run("invalid fail mode", func(t *testing.T) {
		t.Parallel()
		_, err := New(CreateParams{
			GatewayID: gwID,
			Name:      "mcp-consumer",
			Type:      TypeMCP,
			MCP:       &MCPPolicy{FailMode: "explode"},
		})
		if !errors.Is(err, ErrInvalidFailMode) {
			t.Fatalf("error = %v, want ErrInvalidFailMode", err)
		}
	})
}
