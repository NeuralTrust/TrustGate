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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestModelPolicies_Validate(t *testing.T) {
	t.Parallel()
	be1 := ids.New[ids.RegistryKind]()
	be2 := ids.New[ids.RegistryKind]()
	known := map[ids.RegistryID]struct{}{be1: {}, be2: {}}

	tests := []struct {
		name     string
		policies ModelPolicies
		wantErr  bool
	}{
		{
			name:     "nil policies passthrough",
			policies: nil,
			wantErr:  false,
		},
		{
			name:     "nil allowed is passthrough",
			policies: ModelPolicies{be1: {}},
			wantErr:  false,
		},
		{
			name:     "explicit empty allowed is rejected",
			policies: ModelPolicies{be1: {Allowed: []string{}}},
			wantErr:  true,
		},
		{
			name:     "default in allowed is valid",
			policies: ModelPolicies{be1: {Allowed: []string{"gpt-4o", "gpt-4o-mini"}, Default: "gpt-4o"}},
			wantErr:  false,
		},
		{
			name:     "default not in allowed",
			policies: ModelPolicies{be1: {Allowed: []string{"gpt-4o"}, Default: "claude-3"}},
			wantErr:  true,
		},
		{
			name:     "unknown backend",
			policies: ModelPolicies{ids.New[ids.RegistryKind](): {Allowed: []string{"gpt-4o"}}},
			wantErr:  true,
		},
		{
			name:     "duplicate model",
			policies: ModelPolicies{be1: {Allowed: []string{"gpt-4o", "gpt-4o"}}},
			wantErr:  true,
		},
		{
			name:     "default without allowed is allowed",
			policies: ModelPolicies{be2: {Default: "any-model"}},
			wantErr:  false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.policies.Validate(known)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, commonerrors.ErrValidation) {
					t.Fatalf("expected validation error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestModelPolicies_ValueScanRoundTrip(t *testing.T) {
	t.Parallel()
	be := ids.New[ids.RegistryKind]()
	original := ModelPolicies{be: {Allowed: []string{"gpt-4o"}, Default: "gpt-4o"}}

	value, err := original.Value()
	if err != nil {
		t.Fatalf("Value error: %v", err)
	}
	raw, ok := value.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", value)
	}

	var decoded ModelPolicies
	if err := decoded.Scan(raw); err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	policy, ok := decoded.For(be)
	if !ok {
		t.Fatal("expected policy for backend")
	}
	if policy.Default != "gpt-4o" || len(policy.Allowed) != 1 || policy.Allowed[0] != "gpt-4o" {
		t.Fatalf("round-trip mismatch: %+v", policy)
	}
}
