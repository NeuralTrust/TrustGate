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

package proxy

import (
	"encoding/json"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginErrorResult_IncludesTypeWhenSet(t *testing.T) {
	pe := &appplugins.PluginError{
		StatusCode: 403,
		Type:       "tool_not_in_list",
		Message:    "tool not allowed",
	}

	res := pluginErrorResult(pe)
	require.NotNil(t, res)
	assert.Equal(t, 403, res.StatusCode)

	var payload map[string]string
	require.NoError(t, json.Unmarshal(res.Body, &payload))
	assert.Equal(t, "plugin_rejected", payload["error"])
	assert.Equal(t, "tool not allowed", payload["message"])
	assert.Equal(t, "tool_not_in_list", payload["type"])
}

func TestPluginErrorResult_OmitsTypeWhenEmpty(t *testing.T) {
	pe := &appplugins.PluginError{
		StatusCode: 429,
		Message:    "too many",
	}

	res := pluginErrorResult(pe)
	require.NotNil(t, res)
	assert.Equal(t, 429, res.StatusCode)

	var payload map[string]string
	require.NoError(t, json.Unmarshal(res.Body, &payload))
	assert.Equal(t, map[string]string{"error": "plugin_rejected", "message": "too many"}, payload)
	_, hasType := payload["type"]
	assert.False(t, hasType)
}
