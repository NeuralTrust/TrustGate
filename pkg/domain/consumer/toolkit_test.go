package consumer

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
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
		{"prefix match", regA, "repo://github/neuraltrust/agentgateway", true},
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

	t.Run("empty toolkit allows everything", func(t *testing.T) {
		t.Parallel()
		if !(Toolkit{}).AllowsResource(regA, "anything://x") {
			t.Fatal("empty toolkit must allow every resource")
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
			Path:        "/llm",
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
			Path:        "/mcp/dev",
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
			Path:      "/mcp/dev",
			MCP:       &MCPPolicy{FailMode: "explode"},
		})
		if !errors.Is(err, ErrInvalidFailMode) {
			t.Fatalf("error = %v, want ErrInvalidFailMode", err)
		}
	})
}
