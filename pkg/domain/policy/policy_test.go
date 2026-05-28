package policy

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/google/uuid"
)

func validPlugin() Plugin {
	return Plugin{
		Name:     "rate_limiter",
		Enabled:  true,
		Stage:    StagePreRequest,
		Priority: 0,
		Settings: map[string]interface{}{"limit": 100},
	}
}

func TestPolicy_New_HappyPath(t *testing.T) {
	t.Parallel()
	gwID := uuid.New()
	p, err := New(CreateParams{
		GatewayID: gwID,
		Name:      "default",
		Plugins:   Plugins{validPlugin()},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.ID == uuid.Nil {
		t.Fatal("ID is zero")
	}
	if p.GatewayID != gwID {
		t.Fatalf("GatewayID = %s, want %s", p.GatewayID, gwID)
	}
	if len(p.Plugins) != 1 {
		t.Fatalf("Plugins len = %d, want 1", len(p.Plugins))
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Fatal("timestamps are zero")
	}
}

func TestPolicy_New_DefaultsPluginsToEmptySlice(t *testing.T) {
	t.Parallel()
	p, err := New(CreateParams{
		GatewayID: uuid.New(),
		Name:      "no-plugins",
		Plugins:   nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Plugins == nil {
		t.Fatal("Plugins should be a non-nil empty slice")
	}
	if len(p.Plugins) != 0 {
		t.Fatalf("len = %d, want 0", len(p.Plugins))
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
			name:    "nil gateway id",
			mutate:  func(p *Policy) { p.GatewayID = uuid.Nil },
			wantErr: ErrInvalidGatewayID,
		},
		{
			name: "plugin without name",
			mutate: func(p *Policy) {
				p.Plugins = Plugins{{Stage: StagePreRequest}}
			},
			wantErr: ErrInvalidPlugin,
		},
		{
			name: "plugin with unknown stage",
			mutate: func(p *Policy) {
				p.Plugins = Plugins{{Name: "x", Stage: Stage("bogus")}}
			},
			wantErr: ErrInvalidStage,
		},
		{
			name: "duplicate plugin name + stage",
			mutate: func(p *Policy) {
				p.Plugins = Plugins{validPlugin(), validPlugin()}
			},
			wantErr: ErrDuplicatePlugin,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &Policy{
				ID:        uuid.New(),
				GatewayID: uuid.New(),
				Name:      "x",
				Plugins:   Plugins{validPlugin()},
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
		ID:        uuid.New(),
		GatewayID: uuid.New(),
		Name:      "all-stages",
		Plugins: Plugins{
			{Name: "a", Stage: StagePreRequest},
			{Name: "b", Stage: StagePostRequest},
			{Name: "c", Stage: StagePreResponse},
			{Name: "d", Stage: StagePostResponse},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicy_Rehydrate(t *testing.T) {
	t.Parallel()
	id, gwID := uuid.New(), uuid.New()
	now := time.Now().UTC()
	p := Rehydrate(id, gwID, "x", Plugins{validPlugin()}, now, now)
	if p.ID != id || p.GatewayID != gwID {
		t.Fatal("identity mismatch after rehydrate")
	}
	if len(p.Plugins) != 1 {
		t.Fatalf("Plugins len = %d, want 1", len(p.Plugins))
	}
	if !p.CreatedAt.Equal(now) {
		t.Fatal("CreatedAt mismatch")
	}
}

func TestPlugins_ValueAndScan(t *testing.T) {
	t.Parallel()
	original := Plugins{
		{Name: "a", Stage: StagePreRequest, Priority: 1, Enabled: true, Settings: map[string]interface{}{"k": "v"}},
		{Name: "b", Stage: StagePostResponse, Priority: 2},
	}
	v, err := original.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	bytes, ok := v.([]byte)
	if !ok {
		t.Fatalf("Value returned %T, want []byte", v)
	}
	var rt Plugins
	if err := rt.Scan(bytes); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rt) != len(original) {
		t.Fatalf("len = %d, want %d", len(rt), len(original))
	}
	for i := range original {
		if rt[i].Name != original[i].Name || rt[i].Stage != original[i].Stage {
			t.Fatalf("mismatch at %d: %+v vs %+v", i, rt[i], original[i])
		}
	}
}

func TestPlugins_Scan_Nil(t *testing.T) {
	t.Parallel()
	var ps Plugins
	if err := ps.Scan(nil); err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if ps == nil || len(ps) != 0 {
		t.Fatalf("expected empty non-nil slice, got %v", ps)
	}
}

func TestPlugins_Value_EmptyReturnsEmptyArray(t *testing.T) {
	t.Parallel()
	var ps Plugins
	v, err := ps.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	bytes, ok := v.([]byte)
	if !ok {
		t.Fatalf("Value returned %T, want []byte", v)
	}
	if string(bytes) != "[]" {
		t.Fatalf("got %q, want []", string(bytes))
	}
}
