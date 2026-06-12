package consumer

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

func validParams() CreateParams {
	return CreateParams{
		GatewayID:   ids.New[ids.GatewayKind](),
		Name:        "openai-chat",
		Type:        TypeLLM,
		Path:        "/v1/chat/completions",
		RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()},
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
	if !c.Active {
		t.Fatal("Active should default to true")
	}
	if c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() {
		t.Fatal("timestamps are zero")
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
			name:    "empty path",
			mutate:  func(c *Consumer) { c.Path = "" },
			wantErr: ErrInvalidPath,
		},
		{
			name:    "invalid algorithm",
			mutate:  func(c *Consumer) { c.Algorithm = "bogus" },
			wantErr: ErrInvalidAlgorithm,
		},
		{
			name:    "semantic without embedding",
			mutate:  func(c *Consumer) { c.Algorithm = "semantic" },
			wantErr: ErrInvalidEmbeddingConfig,
		},
		{
			name: "duplicate backend",
			mutate: func(c *Consumer) {
				id := ids.New[ids.RegistryKind]()
				c.RegistryIDs = []ids.RegistryID{id, id}
			},
			wantErr: registrydomain.ErrInvalidRegistryID,
		},
		{
			name:    "nil backend uuid",
			mutate:  func(c *Consumer) { c.RegistryIDs = []ids.RegistryID{{}} },
			wantErr: registrydomain.ErrInvalidRegistryID,
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
				Path:        "/v1/chat",
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
		Path:        "/v1/messages",
		Algorithm:   "round-robin",
		Headers:     map[string]string{"X-K": "v"},
		Active:      true,
		RegistryIDs: []ids.RegistryID{beID},
		Toolkit:     toolkit,
		FailMode:    FailModeOpen,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if c.ID != id || c.GatewayID != gwID {
		t.Fatal("identity mismatch after rehydrate")
	}
	if c.Type != TypeMCP {
		t.Fatalf("Type = %q", c.Type)
	}
	if c.Path != "/v1/messages" {
		t.Fatalf("Path = %q", c.Path)
	}
	if !c.CreatedAt.Equal(now) {
		t.Fatal("CreatedAt mismatch")
	}
	if len(c.Toolkit) != 1 || c.Toolkit[0].Tool != "search" || c.Toolkit[0].ExposeAs != "gh_search" {
		t.Fatalf("Toolkit lost on rehydrate: %+v", c.Toolkit)
	}
	if c.FailMode != FailModeOpen {
		t.Fatalf("FailMode = %q, want %q", c.FailMode, FailModeOpen)
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
