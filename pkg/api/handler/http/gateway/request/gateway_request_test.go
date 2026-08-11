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
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
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
