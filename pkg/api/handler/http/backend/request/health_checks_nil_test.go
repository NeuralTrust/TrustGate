package request

import "testing"

func TestCreateBackendRequest_ToHealthChecks_NilField(t *testing.T) {
	t.Parallel()
	r := CreateBackendRequest{}
	got := r.ToHealthChecks()
	if got != nil {
		t.Fatalf("expected nil HealthChecks when field is omitted, got %+v", got)
	}
}

func TestUpdateBackendRequest_ToHealthChecks_NilField(t *testing.T) {
	t.Parallel()
	r := UpdateBackendRequest{}
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
