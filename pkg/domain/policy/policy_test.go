package policy

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestPolicy_New_HappyPath(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p, err := NewPolicy(gwID, "default", "rate_limiter", true, 10, false,
		map[string]any{"limit": 100}, []Stage{StagePreRequest})
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
	if !p.Enabled || p.Priority != 10 {
		t.Fatalf("unexpected enabled/priority: %+v", p)
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Fatal("timestamps are zero")
	}
}

func TestPolicy_New_AllowsEmptyStages(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(ids.New[ids.GatewayKind](), "no-stages", "cors", true, 0, false, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Stages) != 0 {
		t.Fatalf("Stages len = %d, want 0", len(p.Stages))
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
	p := Rehydrate(id, gwID, "x", "cors", true, 5, true,
		map[string]any{"k": "v"}, []Stage{StagePreRequest}, now, now)
	if p.ID != id || p.GatewayID != gwID {
		t.Fatal("identity mismatch after rehydrate")
	}
	if p.Slug != "cors" || !p.Enabled || p.Priority != 5 || !p.Parallel {
		t.Fatalf("unexpected fields after rehydrate: %+v", p)
	}
	if !p.CreatedAt.Equal(now) {
		t.Fatal("CreatedAt mismatch")
	}
}
