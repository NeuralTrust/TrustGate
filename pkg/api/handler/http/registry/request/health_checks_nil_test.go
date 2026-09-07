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

import "testing"

func TestCreateRegistryRequest_ToLLMTarget_NilHealthChecks(t *testing.T) {
	t.Parallel()
	r := CreateRegistryRequest{Provider: "openai"}
	got := r.ToLLMTarget()
	if got == nil {
		t.Fatal("expected LLM target for LLM request")
		return
	}
	if got.HealthChecks != nil {
		t.Fatalf("expected nil HealthChecks when field is omitted, got %+v", got.HealthChecks)
	}
}

func TestUpdateRegistryRequest_ToHealthChecks_NilField(t *testing.T) {
	t.Parallel()
	r := UpdateRegistryRequest{}
	got := r.ToHealthChecks()
	if got != nil {
		t.Fatalf("expected nil HealthChecks when field is omitted, got %+v", got)
	}
}

func TestPricingRequest_ToDomain(t *testing.T) {
	t.Parallel()
	var p *PricingRequest
	if got := p.ToDomain(); got != nil {
		t.Fatalf("expected nil from nil receiver, got %+v", got)
	}
	got := (&PricingRequest{
		Discount:  0.2,
		Overrides: map[string]PriceOverrideRequest{"gpt-4o": {Input: 0.0000015, Output: 0.000006}},
	}).ToDomain()
	if got == nil || got.Discount != 0.2 || got.Overrides["gpt-4o"].Input != 0.0000015 {
		t.Fatalf("ToDomain mismatch: %+v", got)
	}
}

func TestCreateRegistryRequest_Validate_RejectsBadDiscount(t *testing.T) {
	t.Parallel()
	r := CreateRegistryRequest{
		Name:     "openai",
		Provider: "openai",
		Auth:     &TargetAuthRequest{Type: "api_key", APIKey: &APIKeyAuthRequest{APIKey: "sk-1"}},
		Pricing:  &PricingRequest{Discount: 1.5},
	}
	if err := r.Validate(); err == nil {
		t.Fatal("expected validation error for discount > 1")
	}
}

func TestHealthChecksRequest_ToDomain_NilReceiver(t *testing.T) {
	t.Parallel()
	var h *HealthChecksRequest
	if got := h.ToDomain(); got != nil {
		t.Fatalf("expected nil from nil receiver, got %+v", got)
	}
}
