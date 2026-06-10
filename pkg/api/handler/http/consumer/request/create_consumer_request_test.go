package request

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/google/uuid"
)

func TestCreateConsumerRequest_ToRegistryBindings(t *testing.T) {
	t.Parallel()
	reg1 := uuid.NewString()
	reg2 := uuid.NewString()

	req := CreateConsumerRequest{Registries: []RegistryBindingRequest{
		{ID: reg1, ModelPolicies: &ModelPolicyRequest{Allowed: []string{"gpt-4o", "gpt-4o-mini"}, Default: "gpt-4o"}},
		{ID: reg2},
	}}

	registryIDs, policies, err := req.ToRegistryBindings()
	if err != nil {
		t.Fatalf("ToRegistryBindings() error = %v", err)
	}
	if len(registryIDs) != 2 {
		t.Fatalf("expected 2 registry ids, got %d", len(registryIDs))
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	id1, _ := ids.Parse[ids.RegistryKind](reg1)
	policy, ok := policies.For(id1)
	if !ok {
		t.Fatalf("policy for %s missing", reg1)
	}
	if policy.Default != "gpt-4o" {
		t.Fatalf("policy default = %q, want gpt-4o", policy.Default)
	}
}

func TestCreateConsumerRequest_ToRegistryBindings_Empty(t *testing.T) {
	t.Parallel()
	registryIDs, policies, err := CreateConsumerRequest{}.ToRegistryBindings()
	if err != nil {
		t.Fatalf("ToRegistryBindings() error = %v", err)
	}
	if registryIDs != nil || policies != nil {
		t.Fatalf("expected nil outputs, got ids=%v policies=%v", registryIDs, policies)
	}
}

func TestCreateConsumerRequest_ToRegistryBindings_InvalidID(t *testing.T) {
	t.Parallel()
	req := CreateConsumerRequest{Registries: []RegistryBindingRequest{{ID: "not-a-uuid"}}}
	if _, _, err := req.ToRegistryBindings(); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestCreateConsumerRequest_ToRegistryBindings_DuplicateID(t *testing.T) {
	t.Parallel()
	reg := uuid.NewString()
	req := CreateConsumerRequest{Registries: []RegistryBindingRequest{{ID: reg}, {ID: reg}}}
	if _, _, err := req.ToRegistryBindings(); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("expected validation error for duplicate id, got %v", err)
	}
}

func TestUpdateConsumerRequest_ToModelPolicies_NestedRegistries(t *testing.T) {
	t.Parallel()
	if got, err := (UpdateConsumerRequest{}).ToModelPolicies(); err != nil || got != nil {
		t.Fatalf("omitted registries: got=%v err=%v, want nil,nil", got, err)
	}

	reg := uuid.NewString()
	bindings := []RegistryBindingRequest{
		{ID: reg, ModelPolicies: &ModelPolicyRequest{Allowed: []string{"gpt-4o"}, Default: "gpt-4o"}},
	}
	got, err := (UpdateConsumerRequest{Registries: &bindings}).ToModelPolicies()
	if err != nil {
		t.Fatalf("ToModelPolicies() error = %v", err)
	}
	if got == nil || len(*got) != 1 {
		t.Fatalf("expected 1 policy, got %v", got)
	}

	empty := []RegistryBindingRequest{{ID: reg}}
	got, err = (UpdateConsumerRequest{Registries: &empty}).ToModelPolicies()
	if err != nil {
		t.Fatalf("ToModelPolicies() error = %v", err)
	}
	if got == nil || len(*got) != 0 {
		t.Fatalf("registries without policies must clear the map, got %v", got)
	}
}
