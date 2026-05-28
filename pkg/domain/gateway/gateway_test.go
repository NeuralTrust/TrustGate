package gateway

import (
	"errors"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/google/uuid"
)

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		gwName      string
		gwDesc      string
		wantErr     error
		wantTrimmed string
	}{
		{name: "happy path", gwName: "alpha", gwDesc: "primary"},
		{name: "trims whitespace", gwName: "  alpha  ", gwDesc: "primary", wantTrimmed: "alpha"},
		{name: "empty name rejected", gwName: "", gwDesc: "", wantErr: ErrInvalidName},
		{name: "whitespace-only name rejected", gwName: "   ", gwDesc: "", wantErr: ErrInvalidName},
		{name: "name over limit rejected", gwName: strings.Repeat("x", MaxNameLength+1), gwDesc: "", wantErr: ErrInvalidName},
		{name: "description over limit rejected", gwName: "alpha", gwDesc: strings.Repeat("x", MaxDescriptionLength+1), wantErr: ErrInvalidDescription},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g, err := New(tc.gwName, tc.gwDesc)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if g.ID == uuid.Nil {
				t.Fatal("ID is zero")
			}
			wantName := tc.gwName
			if tc.wantTrimmed != "" {
				wantName = tc.wantTrimmed
			}
			if g.Name != wantName {
				t.Fatalf("Name = %q, want %q", g.Name, wantName)
			}
			if g.Description != tc.gwDesc {
				t.Fatalf("Description = %q, want %q", g.Description, tc.gwDesc)
			}
			if g.CreatedAt.IsZero() || g.UpdatedAt.IsZero() {
				t.Fatal("timestamps not set")
			}
			if !g.CreatedAt.Equal(g.UpdatedAt) {
				t.Fatalf("CreatedAt != UpdatedAt on construction")
			}
		})
	}
}

func TestValidationErrorsWrapCommonSentinel(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrInvalidName, commonerrors.ErrValidation) {
		t.Fatal("ErrInvalidName must wrap commonerrors.ErrValidation")
	}
	if !errors.Is(ErrInvalidDescription, commonerrors.ErrValidation) {
		t.Fatal("ErrInvalidDescription must wrap commonerrors.ErrValidation")
	}
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

func TestRename(t *testing.T) {
	t.Parallel()

	g, err := New("alpha", "")
	if err != nil {
		t.Fatalf("setup New: %v", err)
	}
	original := g.UpdatedAt

	if err := g.Rename(""); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("empty rename err = %v, want ErrInvalidName", err)
	}
	if err := g.Rename(strings.Repeat("y", MaxNameLength+1)); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("overlong rename err = %v, want ErrInvalidName", err)
	}
	if g.Name != "alpha" {
		t.Fatalf("Name mutated on failure: %q", g.Name)
	}
	if !g.UpdatedAt.Equal(original) {
		t.Fatalf("UpdatedAt mutated on failure")
	}

	if err := g.Rename("beta"); err != nil {
		t.Fatalf("happy rename: %v", err)
	}
	if g.Name != "beta" {
		t.Fatalf("Name = %q, want beta", g.Name)
	}
	if !g.UpdatedAt.After(original) {
		t.Fatalf("UpdatedAt not bumped on successful rename")
	}
}

func TestSetDescription(t *testing.T) {
	t.Parallel()

	g, err := New("alpha", "v1")
	if err != nil {
		t.Fatalf("setup New: %v", err)
	}
	original := g.UpdatedAt

	if err := g.SetDescription(strings.Repeat("z", MaxDescriptionLength+1)); !errors.Is(err, ErrInvalidDescription) {
		t.Fatalf("overlong desc err = %v, want ErrInvalidDescription", err)
	}
	if g.Description != "v1" {
		t.Fatalf("Description mutated on failure: %q", g.Description)
	}

	if err := g.SetDescription("v2"); err != nil {
		t.Fatalf("happy SetDescription: %v", err)
	}
	if g.Description != "v2" {
		t.Fatalf("Description = %q, want v2", g.Description)
	}
	if !g.UpdatedAt.After(original) {
		t.Fatalf("UpdatedAt not bumped on successful SetDescription")
	}
}

func TestRehydrate(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	g, err := New("alpha", "")
	if err != nil {
		t.Fatalf("setup New: %v", err)
	}
	rehydrated := Rehydrate(id, "raw  name", "raw desc", g.CreatedAt, g.UpdatedAt)
	if rehydrated.ID != id {
		t.Fatalf("ID = %s, want %s", rehydrated.ID, id)
	}
	if rehydrated.Name != "raw  name" {
		t.Fatalf("Rehydrate must not run validation; Name = %q", rehydrated.Name)
	}
}
