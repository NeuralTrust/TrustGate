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

package consumer

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestLBConfig_Validate(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	policies := ModelPolicies{
		registryID: {Allowed: []string{"gpt-4o"}},
	}
	tests := []struct {
		name   string
		config *LBConfig
	}{
		{
			name: "member outside policy",
			config: &LBConfig{
				Enabled: true,
				Members: []LBPoolMember{
					{RegistryID: ids.New[ids.RegistryKind](), Models: []string{"gpt-4o"}},
				},
			},
		},
		{
			name: "semantic without embedding",
			config: &LBConfig{
				Enabled:   true,
				Algorithm: "semantic",
				Members: []LBPoolMember{
					{RegistryID: registryID, Models: []string{"gpt-4o"}},
				},
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.config.Validate(policies)
			if !errors.Is(err, ErrInvalidLBConfig) {
				t.Fatalf("err = %v, want ErrInvalidLBConfig", err)
			}
		})
	}
}
