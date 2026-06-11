package consumer

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func validParams() CreateParams {
	return CreateParams{
		GatewayID:   ids.New[ids.GatewayKind](),
		Name:        "openai-chat",
		Type:        TypeLLM,
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
	// Registries are attached after creation via the association endpoints, so a
	// freshly-created consumer is allowed to have none.
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
	c := Rehydrate(
		id, gwID, "x", TypeMCP,
		"X84Yhsy8", RoutingModeInline, nil,
		map[string]string{"X-K": "v"},
		true,
		[]ids.RegistryID{beID}, nil, nil,
		nil,
		nil,
		now, now,
	)
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
