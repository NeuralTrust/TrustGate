package gateway

import (
	"encoding/json"
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		g, err := New("alpha")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g.ID.IsNil() {
			t.Fatal("ID is zero")
		}
		if g.Name != "alpha" {
			t.Fatalf("Name = %q, want alpha", g.Name)
		}
		if g.Status != "active" {
			t.Fatalf("Status = %q, want active (default)", g.Status)
		}
		if g.CreatedAt.IsZero() || g.UpdatedAt.IsZero() {
			t.Fatal("timestamps not set")
		}
		if !g.CreatedAt.Equal(g.UpdatedAt) {
			t.Fatal("CreatedAt != UpdatedAt on construction")
		}
	})

	t.Run("empty name rejected", func(t *testing.T) {
		t.Parallel()
		g, err := New("")
		if err == nil {
			t.Fatal("expected error for empty name, got nil")
		}
		if g != nil {
			t.Fatalf("expected nil aggregate on error, got %+v", g)
		}
	})
}

func TestValidate_StatusDefault(t *testing.T) {
	t.Parallel()
	g := &Gateway{Name: "alpha"}
	if err := g.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Status != "active" {
		t.Fatalf("Status default = %q, want active", g.Status)
	}
}

func TestValidate_StatusPreserved(t *testing.T) {
	t.Parallel()
	g := &Gateway{Name: "alpha", Status: "paused"}
	if err := g.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Status != "paused" {
		t.Fatalf("Status mutated to %q, want paused", g.Status)
	}
}

func TestValidate_NameRequired(t *testing.T) {
	t.Parallel()
	g := &Gateway{}
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestValidate_DomainNormalized(t *testing.T) {
	t.Parallel()
	g := &Gateway{Name: "alpha", Domain: "  Tenant-A.Example.COM "}
	if err := g.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Domain != "tenant-a.example.com" {
		t.Fatalf("Domain = %q, want normalized lowercase", g.Domain)
	}
}

func TestValidate_DomainRejectsNonHostnames(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"https://x.com", "x.com/path", "x.com:8082", "two words"} {
		g := &Gateway{Name: "alpha", Domain: bad}
		if err := g.Validate(); !errors.Is(err, ErrInvalidDomain) {
			t.Fatalf("Domain %q: err = %v, want ErrInvalidDomain", bad, err)
		}
	}
}

func TestValidate_EmptyDomainAllowed(t *testing.T) {
	t.Parallel()
	g := &Gateway{Name: "alpha"}
	if err := g.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Domain != "" {
		t.Fatalf("Domain = %q, want empty", g.Domain)
	}
}

func TestRepositorySentinelsWrapCommonErrors(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrNotFound, commonerrors.ErrNotFound) {
		t.Fatal("ErrNotFound must wrap commonerrors.ErrNotFound")
	}
	if !errors.Is(ErrAlreadyExists, commonerrors.ErrAlreadyExists) {
		t.Fatal("ErrAlreadyExists must wrap commonerrors.ErrAlreadyExists")
	}
	if !errors.Is(ErrHasDependents, commonerrors.ErrHasDependents) {
		t.Fatal("ErrHasDependents must wrap commonerrors.ErrHasDependents")
	}
}

func TestClientTLSConfig_RoundTrip(t *testing.T) {
	t.Parallel()
	original := ClientTLSConfig{
		"api.example.com": json.RawMessage(`{"insecure":false}`),
	}
	v, err := original.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	bytes, ok := v.([]byte)
	if !ok {
		t.Fatalf("Value type = %T, want []byte", v)
	}
	var out ClientTLSConfig
	if err := out.Scan(bytes); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("Scan length = %d, want 1", len(out))
	}
	if string(out["api.example.com"]) != `{"insecure":false}` {
		t.Fatalf("Scan value = %s", string(out["api.example.com"]))
	}
}

func TestClientTLSConfig_NilRoundTrip(t *testing.T) {
	t.Parallel()
	var nilCfg ClientTLSConfig
	v, err := nilCfg.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if v != nil {
		t.Fatalf("Value = %v, want nil for nil ClientTLSConfig", v)
	}
}
