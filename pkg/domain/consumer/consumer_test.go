package consumer

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	backenddomain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/google/uuid"
)

func validParams() CreateParams {
	return CreateParams{
		GatewayID:  uuid.New(),
		Name:       "openai-chat",
		Type:       TypeLLM,
		Path:       "/v1/chat/completions",
		BackendIDs: []uuid.UUID{uuid.New()},
	}
}

func TestConsumer_New_HappyPath(t *testing.T) {
	t.Parallel()
	p := validParams()
	c, err := New(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ID == uuid.Nil {
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
			mutate:  func(c *Consumer) { c.GatewayID = uuid.Nil },
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
			name:    "no backends",
			mutate:  func(c *Consumer) { c.BackendIDs = nil },
			wantErr: ErrNoBackends,
		},
		{
			name: "duplicate backend",
			mutate: func(c *Consumer) {
				id := uuid.New()
				c.BackendIDs = []uuid.UUID{id, id}
			},
			wantErr: backenddomain.ErrInvalidBackendID,
		},
		{
			name:    "nil backend uuid",
			mutate:  func(c *Consumer) { c.BackendIDs = []uuid.UUID{uuid.Nil} },
			wantErr: backenddomain.ErrInvalidBackendID,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Consumer{
				ID:         uuid.New(),
				GatewayID:  uuid.New(),
				Name:       "x",
				Type:       TypeLLM,
				Path:       "/v1/chat",
				BackendIDs: []uuid.UUID{uuid.New()},
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

func TestConsumer_AttachBackend(t *testing.T) {
	t.Parallel()
	c := &Consumer{BackendIDs: nil}
	id1 := uuid.New()
	if !c.AttachBackend(id1) {
		t.Fatal("AttachBackend should report true on new id")
	}
	if c.AttachBackend(id1) {
		t.Fatal("AttachBackend should be idempotent")
	}
	if c.AttachBackend(uuid.Nil) {
		t.Fatal("AttachBackend(uuid.Nil) should be rejected")
	}
	if len(c.BackendIDs) != 1 || c.BackendIDs[0] != id1 {
		t.Fatalf("BackendIDs = %v", c.BackendIDs)
	}
}

func TestConsumer_DetachBackend(t *testing.T) {
	t.Parallel()
	id1, id2 := uuid.New(), uuid.New()
	c := &Consumer{BackendIDs: []uuid.UUID{id1, id2}}
	if !c.DetachBackend(id1) {
		t.Fatal("DetachBackend should report true on present id")
	}
	if c.DetachBackend(id1) {
		t.Fatal("DetachBackend(missing) should report false")
	}
	if len(c.BackendIDs) != 1 || c.BackendIDs[0] != id2 {
		t.Fatalf("BackendIDs = %v", c.BackendIDs)
	}
}

func TestConsumer_Rehydrate(t *testing.T) {
	t.Parallel()
	id, gwID, beID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	c := Rehydrate(
		id, gwID, "x", TypeMCP,
		"/v1/messages", "round-robin", nil,
		map[string]string{"X-K": "v"},
		true,
		[]uuid.UUID{beID}, nil, nil,
		nil,
		now, now,
	)
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
