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

package toolinjection

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginInjectKeepsClientToolBytesAndMarkers(t *testing.T) {
	t.Parallel()
	const clientTool = `{"name":"a","input_schema":{"type":"object","properties":{"z":{},"y":{}}},"cache_control":{"type":"ephemeral","ttl":"1h"}}`
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"tools":[` + clientTool + `],"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"enabled","budget_tokens":1024}}`

	res := execPreRequest(t, injectSettings(), string(adapter.FormatAnthropic), []byte(body))

	out := string(res.RequestBody)
	assert.True(t, strings.HasPrefix(out, `{"model":"claude-sonnet-4-5","max_tokens":64,"tools":[`+clientTool+`,{"name":"safety_check"`), out)
	assert.True(t, strings.HasSuffix(out, `],"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"enabled","budget_tokens":1024}}`), out)
	decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatAnthropic)
	require.NoError(t, err)
	require.Len(t, decoded.Tools, 2)
	require.NotNil(t, decoded.Tools[0].Cache)
	assert.Equal(t, adapter.CacheTTL1h, decoded.Tools[0].Cache.TTL)
	assert.Nil(t, decoded.Tools[1].Cache)
}

func TestPluginInjectGatewayWinsKeepsTheReplacedToolMarker(t *testing.T) {
	t.Parallel()
	settings := injectSettings()
	settings["on_conflict"] = "gateway_wins"
	const kept = `{"name":"a","input_schema":{"type":"object","properties":{"z":{},"y":{}}}}`
	body := `{"model":"claude-sonnet-4-5","max_tokens":64,"tools":[` + kept + `,{"name":"safety_check","description":"client","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`

	res := execPreRequest(t, settings, string(adapter.FormatAnthropic), []byte(body))

	assert.Contains(t, string(res.RequestBody), `"tools":[`+kept+`,`)
	decoded, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatAnthropic)
	require.NoError(t, err)
	require.Len(t, decoded.Tools, 2)
	assert.Equal(t, "gateway", decoded.Tools[1].Description)
	assert.NotNil(t, decoded.Tools[1].Cache)
}

func TestPluginInjectKeepsToolsTheCanonicalDoesNotModel(t *testing.T) {
	t.Parallel()
	body := `{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"a"}]}`

	res := execPreRequest(t, injectSettings(), string(adapter.FormatOpenAIResponses), []byte(body))

	assert.True(t, strings.HasPrefix(string(res.RequestBody), `{"model":"gpt-5","input":"hi","tools":[{"type":"web_search"},{"type":"function","name":"a"},`), string(res.RequestBody))
}

func TestPluginReencodesAnAmbiguousBodyItLeftUnchanged(t *testing.T) {
	t.Parallel()
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"safety_check","parameters":{"type":"object"}}}],` +
		`"Tools":[{"type":"function","function":{"name":"safety_check","parameters":{"type":"object"}}}]}`

	settings := injectSettings()
	settings["on_conflict"] = conflictClientWins

	res := execPreRequest(t, settings, string(adapter.FormatOpenAI), []byte(body))

	assert.False(t, adapter.HasAmbiguousKeys(res.RequestBody), string(res.RequestBody))
}
