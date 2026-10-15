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

package request

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
)

func intPtr(v int) *int { return &v }

func stampedEntitlements(tier string) domain.Entitlements {
	switch tier {
	case "standard":
		return domain.Entitlements{
			Tier:          "standard",
			BurstPerMin:   intPtr(300),
			QuotaPerMonth: intPtr(100_000),
			MaxInstances:  intPtr(5),
		}
	case "enterprise":
		return domain.Entitlements{
			Tier:          "enterprise",
			BurstPerMin:   intPtr(1_000),
			QuotaPerMonth: intPtr(0),
			MaxInstances:  intPtr(5),
		}
	default:
		return domain.Entitlements{
			Tier:          "free",
			BurstPerMin:   intPtr(60),
			QuotaPerMonth: intPtr(10_000),
			MaxInstances:  intPtr(5),
		}
	}
}

func TestCreateGatewayRequest_ValidateSlug(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     CreateGatewayRequest
		wantErr bool
	}{
		{name: "empty slug is accepted (auto-generated)", req: CreateGatewayRequest{Slug: ""}},
		{name: "valid slug is accepted", req: CreateGatewayRequest{Slug: "acme-prod"}},
		{name: "invalid slug is rejected", req: CreateGatewayRequest{Slug: "-bad"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestUpdateGatewayRequest_ValidateSlug(t *testing.T) {
	t.Parallel()
	valid := "acme-prod"
	invalid := "bad_slug"
	empty := ""

	reqValid := UpdateGatewayRequest{Slug: &valid}
	if err := reqValid.Validate(); err != nil {
		t.Fatalf("valid slug rejected: %v", err)
	}
	reqInvalid := UpdateGatewayRequest{Slug: &invalid}
	if err := reqInvalid.Validate(); err == nil {
		t.Fatal("expected invalid slug error, got nil")
	}
	reqEmpty := UpdateGatewayRequest{Slug: &empty}
	if err := reqEmpty.Validate(); err == nil {
		t.Fatal("expected empty slug error, got nil")
	}
}

func TestCreateGatewayRequest_ValidateEntitlements(t *testing.T) {
	t.Parallel()
	free := stampedEntitlements("free")
	standard := stampedEntitlements("standard")
	enterprise := stampedEntitlements("enterprise")
	enterprise.Tier = "Enterprise"

	tests := []struct {
		name     string
		req      CreateGatewayRequest
		wantErr  bool
		wantTier string
	}{
		{name: "nil entitlements ok", req: CreateGatewayRequest{Slug: "acme"}},
		{name: "tier only rejected", req: CreateGatewayRequest{Slug: "acme", Entitlements: &domain.Entitlements{Tier: "free"}}, wantErr: true},
		{name: "stamped free ok", req: CreateGatewayRequest{Slug: "acme", Entitlements: &free}, wantTier: "free"},
		{name: "stamped standard ok", req: CreateGatewayRequest{Slug: "acme", Entitlements: &standard}, wantTier: "standard"},
		{name: "stamped enterprise normalizes tier", req: CreateGatewayRequest{Slug: "acme", Entitlements: &enterprise}, wantTier: "enterprise"},
		{name: "unknown tier rejected", req: CreateGatewayRequest{Slug: "acme", Entitlements: &domain.Entitlements{Tier: "gold", BurstPerMin: intPtr(1), QuotaPerMonth: intPtr(1), MaxInstances: intPtr(1)}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.req.Entitlements != nil && tt.req.Entitlements.Tier != tt.wantTier {
				t.Fatalf("Entitlements.Tier = %q, want %q", tt.req.Entitlements.Tier, tt.wantTier)
			}
		})
	}
}

func TestUpdateGatewayRequest_ValidateEntitlements(t *testing.T) {
	t.Parallel()

	valid := UpdateGatewayRequest{Entitlements: ptr(stampedEntitlements("standard"))}
	if err := valid.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", valid.Entitlements.Tier)
	}

	tierOnly := UpdateGatewayRequest{Entitlements: &domain.Entitlements{Tier: "standard"}}
	if err := tierOnly.Validate(); err == nil {
		t.Fatal("expected error for tier-only entitlements, got nil")
	}

	invalid := UpdateGatewayRequest{Entitlements: &domain.Entitlements{Tier: "gold", BurstPerMin: intPtr(1), QuotaPerMonth: intPtr(1), MaxInstances: intPtr(1)}}
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected error for unknown tier, got nil")
	}
}

func ptr(e domain.Entitlements) *domain.Entitlements { return &e }

func TestUpdateGatewayRequest_ValidateStoreMode(t *testing.T) {
	t.Parallel()
	open := "open"
	curated := "curated"
	none := "none"
	bad := "half-open"
	mixedCase := "Curated"

	for _, mode := range []string{open, curated, none, mixedCase} {
		m := mode
		req := UpdateGatewayRequest{StoreMode: &m}
		if err := req.Validate(); err != nil {
			t.Fatalf("store_mode %q rejected: %v", mode, err)
		}
	}
	// Normalization: mixed case lowercased in place.
	m := mixedCase
	req := UpdateGatewayRequest{StoreMode: &m}
	_ = req.Validate()
	if *req.StoreMode != curated {
		t.Fatalf("store_mode not normalized: got %q", *req.StoreMode)
	}

	reqBad := UpdateGatewayRequest{StoreMode: &bad}
	if err := reqBad.Validate(); err == nil {
		t.Fatal("expected invalid store_mode error, got nil")
	}
}

func TestGatewayRequests_ValidateTrafficLabeling(t *testing.T) {
	t.Parallel()

	valid := &trafficlabel.Config{Enabled: true, RegistryID: "0190e0d2-6c1f-7a5e-9a3b-1f2e3d4c5b6a", Model: "gpt-4o-mini"}
	invalid := map[string]*trafficlabel.Config{
		"no registry":    {Enabled: true, Model: "gpt-4o-mini"},
		"no model":       {Enabled: true, RegistryID: valid.RegistryID},
		"bad registry":   {Enabled: true, RegistryID: "not-a-uuid", Model: "m"},
		"window too big": {Enabled: true, RegistryID: valid.RegistryID, Model: "m", MessageWindow: trafficlabel.MaxMessageWindow + 1},
	}

	if err := (&CreateGatewayRequest{}).Validate(); err != nil {
		t.Fatalf("create without traffic_labeling rejected: %v", err)
	}
	if err := (&CreateGatewayRequest{TrafficLabeling: valid}).Validate(); err != nil {
		t.Fatalf("create with a valid config rejected: %v", err)
	}
	if err := (&UpdateGatewayRequest{TrafficLabeling: valid}).Validate(); err != nil {
		t.Fatalf("update with a valid config rejected: %v", err)
	}
	if err := (&UpdateGatewayRequest{TrafficLabeling: &trafficlabel.Config{Enabled: false}}).Validate(); err != nil {
		t.Fatalf("a disabled config needs no registry: %v", err)
	}

	for label, cfg := range invalid {
		for name, validate := range map[string]func() error{
			"create": (&CreateGatewayRequest{TrafficLabeling: cfg}).Validate,
			"update": (&UpdateGatewayRequest{TrafficLabeling: cfg}).Validate,
		} {
			err := validate()
			if err == nil {
				t.Fatalf("%s accepted %s", name, label)
			}
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("%s error %v does not wrap ErrValidation", name, err)
			}
		}
	}
}

func TestUpdateGatewayRequest_DetectClears(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		`{"traffic_labeling": null}`:               true,
		`{"traffic_labeling":null,"slug":"a"}`:     true,
		`{"traffic_labeling": {"enabled": false}}`: false,
		`{"slug": "a"}`:                            false,
		`not json`:                                 false,
	}
	for body, want := range tests {
		var req UpdateGatewayRequest
		req.DetectClears([]byte(body))
		if req.ClearTrafficLabeling != want {
			t.Fatalf("DetectClears(%s) = %v, want %v", body, req.ClearTrafficLabeling, want)
		}
	}
}
