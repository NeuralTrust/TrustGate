package request

import (
	"encoding/json"
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestCreateRoleRequest_ValidateRejectsModelPolicies(t *testing.T) {
	t.Parallel()

	req := CreateRoleRequest{
		Name: "analyst",
		ModelPolicies: []ModelPolicyRequest{
			{RegistryID: ids.New[ids.RegistryKind]().String(), Allowed: []string{"gpt-4o"}},
		},
	}

	err := req.Validate()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want validation error", err)
	}
}

func TestRoleRequest_ValidateRejectsInvalidIDPMapping(t *testing.T) {
	t.Parallel()

	req := CreateRoleRequest{
		Name:       "analyst",
		IDPMapping: json.RawMessage(`{"match":"all","claims":[{"path":"groups","op":"unknown","values":["admin"]}]}`),
	}

	err := req.Validate()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want validation error", err)
	}
}
