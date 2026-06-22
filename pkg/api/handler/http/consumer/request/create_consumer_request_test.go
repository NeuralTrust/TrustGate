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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func intPtr(v int) *int { return &v }

func TestCreateConsumerRequest_ToRegistryBindings_Weights(t *testing.T) {
	t.Parallel()
	id1 := ids.New[ids.RegistryKind]()
	id2 := ids.New[ids.RegistryKind]()
	req := CreateConsumerRequest{
		Name: "c",
		Registries: []RegistryBindingRequest{
			{ID: id1.String(), Weight: intPtr(5)},
			{ID: id2.String()},
		},
	}

	registryIDs, weights, _, err := req.ToRegistryBindings()
	if err != nil {
		t.Fatalf("ToRegistryBindings error: %v", err)
	}
	if len(registryIDs) != 2 {
		t.Fatalf("registryIDs len = %d, want 2", len(registryIDs))
	}
	if weights[id1] != 5 {
		t.Fatalf("weights[id1] = %d, want 5", weights[id1])
	}
	if weights[id2] != 1 {
		t.Fatalf("weights[id2] = %d, want default 1", weights[id2])
	}
}

func TestCreateConsumerRequest_ToRegistryBindings_RejectsNonPositiveWeight(t *testing.T) {
	t.Parallel()
	req := CreateConsumerRequest{
		Name: "c",
		Registries: []RegistryBindingRequest{
			{ID: ids.New[ids.RegistryKind]().String(), Weight: intPtr(0)},
		},
	}

	_, _, _, err := req.ToRegistryBindings()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestCreateConsumerRequest_ToRegistryBindings_RejectsWeightAboveMax(t *testing.T) {
	t.Parallel()
	req := CreateConsumerRequest{
		Name: "c",
		Registries: []RegistryBindingRequest{
			{ID: ids.New[ids.RegistryKind]().String(), Weight: intPtr(domain.MaxRegistryWeight + 1)},
		},
	}

	_, _, _, err := req.ToRegistryBindings()
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}
