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

func TestConsumer_MCP_RejectsLLMOnlyFields(t *testing.T) {
	t.Parallel()

	t.Run("model policies", func(t *testing.T) {
		t.Parallel()
		p := mcpParams()
		p.ModelPolicies = ModelPolicies{p.RegistryIDs[0]: ModelPolicy{Allowed: []string{"gpt-4o"}}}
		if _, err := New(p); !errors.Is(err, ErrInvalidModelPolicy) {
			t.Fatalf("error = %v, want ErrInvalidModelPolicy", err)
		}
	})

	t.Run("fallback", func(t *testing.T) {
		t.Parallel()
		p := mcpParams()
		p.Fallback = &Fallback{}
		if _, err := New(p); !errors.Is(err, ErrInvalidFallback) {
			t.Fatalf("error = %v, want ErrInvalidFallback", err)
		}
	})
}

func TestConsumer_MCP_DefaultsFailModeClosed(t *testing.T) {
	t.Parallel()
	c, err := New(mcpParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.FailMode != FailModeClosed {
		t.Fatalf("FailMode = %q, want %q", c.FailMode, FailModeClosed)
	}
}

func TestConsumer_NonMCP_RejectsMCPOnlyFields(t *testing.T) {
	t.Parallel()

	t.Run("fail mode", func(t *testing.T) {
		t.Parallel()
		p := validParams()
		p.FailMode = FailModeOpen
		if _, err := New(p); !errors.Is(err, ErrInvalidFailMode) {
			t.Fatalf("error = %v, want ErrInvalidFailMode", err)
		}
	})

	t.Run("toolkit", func(t *testing.T) {
		t.Parallel()
		p := validParams()
		p.Toolkit = Toolkit{{RegistryID: p.RegistryIDs[0], Tool: "x"}}
		if _, err := New(p); !errors.Is(err, ErrInvalidToolkit) {
			t.Fatalf("error = %v, want ErrInvalidToolkit", err)
		}
	})
}
