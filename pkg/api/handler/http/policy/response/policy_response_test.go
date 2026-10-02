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

package response_test

import (
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/response"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/require"
)

func TestFromPolicy_PlacementFlagsAreAlwaysPresent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		policy      domain.Policy
		wantGlobal  bool
		wantMCPWide bool
	}{
		{name: "draft", policy: domain.Policy{}},
		{name: "global", policy: domain.Policy{Global: true}, wantGlobal: true},
		{name: "mcp-wide", policy: domain.Policy{MCPWide: true}, wantMCPWide: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw, err := json.Marshal(response.FromPolicy(&tt.policy, nil))
			require.NoError(t, err)

			var body map[string]any
			require.NoError(t, json.Unmarshal(raw, &body))
			require.Contains(t, body, "global")
			require.Contains(t, body, "mcp_wide")
			require.Equal(t, tt.wantGlobal, body["global"])
			require.Equal(t, tt.wantMCPWide, body["mcp_wide"])
		})
	}
}
