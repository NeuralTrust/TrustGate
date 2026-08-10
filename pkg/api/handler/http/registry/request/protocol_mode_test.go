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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestMCPTargetRequest_ProtocolModeMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mode string
		want domain.MCPProtocolMode
	}{
		{name: "omitted", want: ""},
		{name: "auto", mode: "auto", want: domain.MCPProtocolModeAuto},
		{name: "modern", mode: "modern", want: domain.MCPProtocolModeModern},
		{name: "legacy", mode: "legacy", want: domain.MCPProtocolModeLegacy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := (&MCPTargetRequest{URL: "https://mcp.example.com/mcp", ProtocolMode: tc.mode}).ToDomain()
			if got.ProtocolMode != tc.want {
				t.Fatalf("ProtocolMode = %q, want %q", got.ProtocolMode, tc.want)
			}
		})
	}
}

func TestRegistryRequests_RejectInvalidProtocolMode(t *testing.T) {
	t.Parallel()
	create := CreateRegistryRequest{
		Name:      "mcp",
		Type:      "MCP",
		MCPTarget: &MCPTargetRequest{URL: "https://mcp.example.com/mcp", ProtocolMode: "future"},
	}
	if err := create.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("Create Validate() = %v, want validation error", err)
	}

	update := UpdateRegistryRequest{
		MCPTarget: &MCPTargetRequest{ProtocolMode: "future"},
	}
	if err := update.Validate(); !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("Update Validate() = %v, want validation error", err)
	}
}

func TestMCPRegistryRequest_AcceptsUppercaseHTTPS(t *testing.T) {
	t.Parallel()

	request := CreateRegistryRequest{
		Name: "mcp",
		Type: "MCP",
		MCPTarget: &MCPTargetRequest{
			URL: "HTTPS://MCP.EXAMPLE.COM/mcp",
		},
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("request Validate() = %v, want nil", err)
	}
	if err := request.ToMCPTarget().Validate(); err != nil {
		t.Fatalf("target Validate() = %v, want nil", err)
	}
}
