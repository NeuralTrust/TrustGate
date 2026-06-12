package consumer

import (
	"errors"
	"testing"
)

func mcpParams() CreateParams {
	p := validParams()
	p.Type = TypeMCP
	p.Path = "/v1/mcp/dev"
	return p
}

func TestConsumer_MCP_RejectsLLMPolicy(t *testing.T) {
	t.Parallel()
	p := mcpParams()
	p.LLM = &LLMPolicy{
		ModelPolicies: ModelPolicies{p.RegistryIDs[0]: ModelPolicy{Allowed: []string{"gpt-4o"}}},
	}
	if _, err := New(p); !errors.Is(err, ErrInvalidType) {
		t.Fatalf("error = %v, want ErrInvalidType", err)
	}
}

func TestConsumer_MCP_DefaultsFailModeClosed(t *testing.T) {
	t.Parallel()
	c, err := New(mcpParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.FailMode() != FailModeClosed {
		t.Fatalf("FailMode = %q, want %q", c.FailMode(), FailModeClosed)
	}
}

func TestConsumer_LLM_RejectsMCPPolicy(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.MCP = &MCPPolicy{FailMode: FailModeOpen}
	if _, err := New(p); !errors.Is(err, ErrInvalidType) {
		t.Fatalf("error = %v, want ErrInvalidType", err)
	}
}

func TestConsumer_LLM_DefaultsAlgorithm(t *testing.T) {
	t.Parallel()
	c, err := New(validParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Algorithm() == "" {
		t.Fatal("Algorithm should default for LLM consumers")
	}
}

func TestConsumer_A2A_RejectsPolicies(t *testing.T) {
	t.Parallel()

	t.Run("llm policy", func(t *testing.T) {
		t.Parallel()
		p := validParams()
		p.Type = TypeA2A
		p.LLM = &LLMPolicy{Algorithm: "round-robin"}
		if _, err := New(p); !errors.Is(err, ErrInvalidType) {
			t.Fatalf("error = %v, want ErrInvalidType", err)
		}
	})

	t.Run("mcp policy", func(t *testing.T) {
		t.Parallel()
		p := validParams()
		p.Type = TypeA2A
		p.MCP = &MCPPolicy{}
		if _, err := New(p); !errors.Is(err, ErrInvalidType) {
			t.Fatalf("error = %v, want ErrInvalidType", err)
		}
	})
}
