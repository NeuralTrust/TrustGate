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
		{"duplicate tool", Toolkit{{RegistryID: regA, Tool: "x"}, {RegistryID: regA, Tool: "x"}}},
		{"expose_as on wildcard", Toolkit{{RegistryID: regA, Tool: ToolWildcard, ExposeAs: "y"}}},
		{"duplicate alias", Toolkit{
			{RegistryID: regA, Tool: "x", ExposeAs: "same"},
			{RegistryID: regB, Tool: "y", ExposeAs: "same"},
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
			Toolkit:     Toolkit{{RegistryID: regID, Tool: ToolWildcard}},
		})
		if !errors.Is(err, ErrInvalidToolkit) {
			t.Fatalf("error = %v, want ErrInvalidToolkit", err)
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
			Toolkit:     Toolkit{{RegistryID: regID, Tool: ToolWildcard}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.FailMode != FailModeClosed {
			t.Fatalf("FailMode = %q, want default closed", c.FailMode)
		}
	})

	t.Run("invalid fail mode", func(t *testing.T) {
		t.Parallel()
		_, err := New(CreateParams{
			GatewayID: gwID,
			Name:      "mcp-consumer",
			Type:      TypeMCP,
			Path:      "/mcp/dev",
			FailMode:  "explode",
		})
		if !errors.Is(err, ErrInvalidFailMode) {
			t.Fatalf("error = %v, want ErrInvalidFailMode", err)
		}
	})
}
