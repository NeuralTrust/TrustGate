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
	"encoding/json"
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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

func TestRoleRequest_ValidateRejectsInvalidOIDCMapping(t *testing.T) {
	t.Parallel()

	req := CreateRoleRequest{
		Name:        "analyst",
		OIDCMapping: json.RawMessage(`{"match":"all","claims":[{"path":"groups","op":"unknown","values":["admin"]}]}`),
	}

	err := req.Validate()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want validation error", err)
	}
}
