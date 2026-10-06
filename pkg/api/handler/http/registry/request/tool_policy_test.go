// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func ptr[T any](v T) *T { return &v }

func TestCreateRegistryRequest_ToolPolicy(t *testing.T) {
	t.Parallel()
	mcp := func(policy string) CreateRegistryRequest {
		return CreateRegistryRequest{Name: "m", Type: "MCP", ToolPolicy: policy, MCPTarget: &MCPTargetRequest{URL: "https://x/mcp"}}
	}
	if got := mcp("").ToToolPolicy(); got != domain.ToolPolicyAuto {
		t.Fatalf("absent policy = %q, want auto", got)
	}
	if got := mcp(" Pinned ").ToToolPolicy(); got != domain.ToolPolicyPinned {
		t.Fatalf("policy = %q, want pinned", got)
	}
	if err := mcp("pinned").Validate(); err != nil {
		t.Fatalf("pinned MCP: %v", err)
	}
	if err := mcp("strict").Validate(); !errors.Is(err, domain.ErrInvalidToolPolicy) {
		t.Fatalf("err = %v, want ErrInvalidToolPolicy", err)
	}
}

func TestUpdateRegistryRequest_ToolPolicy(t *testing.T) {
	t.Parallel()
	if got := (UpdateRegistryRequest{}).ToToolPolicy(); got != nil {
		t.Fatalf("absent policy = %q, want nil (unchanged)", *got)
	}
	got := UpdateRegistryRequest{ToolPolicy: ptr("PINNED")}.ToToolPolicy()
	if got == nil || *got != domain.ToolPolicyPinned {
		t.Fatalf("policy = %v, want pinned", got)
	}
	if err := (UpdateRegistryRequest{ToolPolicy: ptr("pinned")}).Validate(); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	if err := (UpdateRegistryRequest{ToolPolicy: ptr("")}).Validate(); err != nil {
		t.Fatalf("empty string normalizes to auto: %v", err)
	}
	if err := (UpdateRegistryRequest{ToolPolicy: ptr("strict")}).Validate(); !errors.Is(err, domain.ErrInvalidToolPolicy) {
		t.Fatalf("err = %v, want ErrInvalidToolPolicy", err)
	}
}
