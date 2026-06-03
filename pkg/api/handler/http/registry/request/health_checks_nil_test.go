package request

import "testing"

func TestCreateRegistryRequest_ToHealthChecks_NilField(t *testing.T) {
	t.Parallel()
	r := CreateRegistryRequest{}
	got := r.ToHealthChecks()
	if got != nil {
		t.Fatalf("expected nil HealthChecks when field is omitted, got %+v", got)
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
