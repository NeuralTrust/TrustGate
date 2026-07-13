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

package plugins

import "testing"

func TestProtocol_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		protocol Protocol
		want     bool
	}{
		{name: "llm", protocol: ProtocolLLM, want: true},
		{name: "mcp", protocol: ProtocolMCP, want: true},
		{name: "a2a", protocol: ProtocolA2A, want: true},
		{name: "empty", protocol: Protocol(""), want: false},
		{name: "unknown", protocol: Protocol("WS"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.protocol.IsValid(); got != tt.want {
				t.Fatalf("Protocol(%q).IsValid() = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}
