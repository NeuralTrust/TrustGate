// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gateway

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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
		if g.Slug != "alpha" {
			t.Fatalf("Slug = %q, want alpha", g.Slug)
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

	t.Run("empty slug is auto-generated", func(t *testing.T) {
		t.Parallel()
		g, err := New("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g == nil {
			t.Fatal("expected gateway, got nil")
		}
		if !IsValidSlug(g.Slug) {
			t.Fatalf("generated slug %q is not a valid DNS label", g.Slug)
		}
	})
}

func TestNewSlug(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		slug, err := NewSlug()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !IsValidSlug(slug) {
			t.Fatalf("generated slug %q is not a valid DNS label", slug)
		}
		if _, dup := seen[slug]; dup {
			t.Fatalf("generated duplicate slug %q", slug)
		}
		seen[slug] = struct{}{}
	}
}

func TestValidate_InvalidSlug(t *testing.T) {
	t.Parallel()
	g := &Gateway{Slug: "-bad"}
	if err := g.Validate(); err == nil {
		t.Fatal("expected invalid slug error, got nil")
	}
}

func TestValidate_StatusDefault(t *testing.T) {
	t.Parallel()
	g := &Gateway{Slug: "alpha"}
	if err := g.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Status != "active" {
		t.Fatalf("Status default = %q, want active", g.Status)
	}
}

func TestValidate_StatusPreserved(t *testing.T) {
	t.Parallel()
	g := &Gateway{Slug: "alpha", Status: "paused"}
	if err := g.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Status != "paused" {
		t.Fatalf("Status mutated to %q, want paused", g.Status)
	}
}

func TestValidate_SlugRequired(t *testing.T) {
	t.Parallel()
	g := &Gateway{}
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for empty slug, got nil")
	}
}

func TestValidate_DomainNormalized(t *testing.T) {
	t.Parallel()
	g := &Gateway{Slug: "alpha", Domain: "  Tenant-A.Example.COM "}
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
		g := &Gateway{Slug: "alpha", Domain: bad}
		if err := g.Validate(); !errors.Is(err, ErrInvalidDomain) {
			t.Fatalf("Domain %q: err = %v, want ErrInvalidDomain", bad, err)
		}
	}
}

func TestValidate_EmptyDomainAllowed(t *testing.T) {
	t.Parallel()
	g := &Gateway{Slug: "alpha"}
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

func TestSanitizeClientMetadata(t *testing.T) {
	t.Parallel()

	t.Run("strips server-only tenant_id", func(t *testing.T) {
		t.Parallel()
		in := map[string]string{MetadataTenantIDKey: "attacker-team", "env": "prod"}
		out := SanitizeClientMetadata(in)
		if _, ok := out[MetadataTenantIDKey]; ok {
			t.Fatalf("tenant_id survived sanitization: %v", out)
		}
		if out["env"] != "prod" {
			t.Fatalf("non-reserved key dropped: %v", out)
		}
		if _, ok := in[MetadataTenantIDKey]; !ok {
			t.Fatal("input map mutated; sanitize must copy")
		}
	})

	t.Run("strips legacy team_id", func(t *testing.T) {
		t.Parallel()
		in := map[string]string{MetadataLegacyTeamIDKey: "team-1", "env": "prod"}
		out := SanitizeClientMetadata(in)
		if _, ok := out[MetadataLegacyTeamIDKey]; ok {
			t.Fatalf("legacy team_id survived sanitization: %v", out)
		}
		if out["env"] != "prod" {
			t.Fatalf("non-reserved key dropped: %v", out)
		}
	})

	t.Run("nil input stays nil", func(t *testing.T) {
		t.Parallel()
		if out := SanitizeClientMetadata(nil); out != nil {
			t.Fatalf("nil input produced %v, want nil", out)
		}
	})

	t.Run("only reserved keys collapse to nil", func(t *testing.T) {
		t.Parallel()
		in := map[string]string{MetadataTenantIDKey: "x", MetadataLegacyTeamIDKey: "y"}
		if out := SanitizeClientMetadata(in); out != nil {
			t.Fatalf("expected nil after removing sole reserved keys, got %v", out)
		}
	})
}

func TestWithTenantID(t *testing.T) {
	t.Parallel()

	t.Run("empty team leaves metadata untouched", func(t *testing.T) {
		t.Parallel()
		in := map[string]string{"env": "prod"}
		out := WithTenantID(in, "")
		if _, ok := out[MetadataTenantIDKey]; ok {
			t.Fatalf("empty teamID injected a key: %v", out)
		}
	})

	t.Run("sets tenant_id while preserving other keys", func(t *testing.T) {
		t.Parallel()
		out := WithTenantID(map[string]string{"env": "prod"}, "team-1")
		if out[MetadataTenantIDKey] != "team-1" {
			t.Fatalf("tenant_id = %q, want team-1", out[MetadataTenantIDKey])
		}
		if out["env"] != "prod" {
			t.Fatalf("existing key lost: %v", out)
		}
	})

	t.Run("initializes nil metadata", func(t *testing.T) {
		t.Parallel()
		out := WithTenantID(nil, "team-1")
		if out[MetadataTenantIDKey] != "team-1" {
			t.Fatalf("tenant_id = %q, want team-1", out[MetadataTenantIDKey])
		}
	})
}

func TestRehydrate_DefaultsEntitlements(t *testing.T) {
	t.Parallel()
	g := Rehydrate(ids.New[ids.GatewayKind](), "acme", "active", "", nil, nil, nil, time.Now().UTC(), time.Now().UTC())
	if g.Entitlements.Tier != TierFree {
		t.Fatalf("Entitlements.Tier = %q, want default %q", g.Entitlements.Tier, TierFree)
	}
}

func TestValidateTier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty defaults to free", in: "", want: TierFree},
		{name: "free", in: "free", want: "free"},
		{name: "standard", in: "standard", want: "standard"},
		{name: "enterprise mixed case is normalized", in: " Enterprise ", want: "enterprise"},
		{name: "unknown tier is rejected", in: "gold", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ValidateTier(tt.in)
			if tt.wantErr {
				if !errors.Is(err, commonerrors.ErrValidation) {
					t.Fatalf("err = %v, want wrapped commonerrors.ErrValidation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ValidateTier(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
