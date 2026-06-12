package request

import "testing"

func TestCreateRegistryRequest_ToLLMTarget_NilHealthChecks(t *testing.T) {
	t.Parallel()
	r := CreateRegistryRequest{Provider: "openai"}
	got := r.ToLLMTarget()
	if got == nil {
		t.Fatal("expected LLM target for LLM request")
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

func TestHealthChecksRequest_ToDomain_NilReceiver(t *testing.T) {
	t.Parallel()
	var h *HealthChecksRequest
	if got := h.ToDomain(); got != nil {
		t.Fatalf("expected nil from nil receiver, got %+v", got)
	}
}
