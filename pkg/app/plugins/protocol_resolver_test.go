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

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtocolResolver_SupportedProtocols(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.Register(&stagePlugin{
		name:      "dual",
		supported: []policy.Stage{policy.StagePreRequest},
		protocols: []Protocol{ProtocolLLM, ProtocolMCP},
	}))
	resolver := NewProtocolResolver(reg)

	t.Run("known plugin returns mapped protocols", func(t *testing.T) {
		got, ok := resolver.SupportedProtocols("dual")
		require.True(t, ok)
		assert.ElementsMatch(t, []string{"LLM", "MCP"}, got)
	})

	t.Run("unknown plugin returns false", func(t *testing.T) {
		got, ok := resolver.SupportedProtocols("missing")
		assert.False(t, ok)
		assert.Nil(t, got)
	})
}
