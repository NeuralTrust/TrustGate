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

package mcp

import (
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestStaticTarget_ProtocolMode(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mode registrydomain.MCPProtocolMode
		want registrydomain.MCPProtocolMode
	}{
		{name: "old target defaults to auto", want: registrydomain.MCPProtocolModeAuto},
		{name: "explicit mode is preserved", mode: registrydomain.MCPProtocolModeModern, want: registrydomain.MCPProtocolModeModern},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := &registrydomain.Registry{
				MCPTarget: &registrydomain.MCPTarget{
					URL:          "https://mcp.example.com/mcp",
					ProtocolMode: tc.mode,
				},
			}
			got := StaticTarget(reg)
			if got.ProtocolMode != tc.want {
				t.Fatalf("ProtocolMode = %q, want %q", got.ProtocolMode, tc.want)
			}
		})
	}
}
