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

package pertoolratelimit

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripToolsKeepsOtherToolsAndMarkers(t *testing.T) {
	t.Parallel()
	const (
		toolA = `{"name":"a","input_schema":{"type":"object","properties":{"z":{},"y":{}}},"cache_control":{"type":"ephemeral"}}`
		toolB = `{"name":"b","input_schema":{"type":"object"}}`
		toolC = `{"name":"c","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral","ttl":"1h"}}`
	)
	body := func(tools string) []byte {
		return []byte(`{"model":"claude-sonnet-4-5","max_tokens":64,"tools":[` + tools + `],"messages":[{"role":"user","content":"hi"}]}`)
	}
	reg := adapter.NewRegistry()
	p := New(nil, reg)

	canonical, err := reg.DecodeRequestFor(body(toolA+","+toolB+","+toolC), adapter.FormatAnthropic)
	require.NoError(t, err)
	res, err := p.stripTools(body(toolA+","+toolB+","+toolC), string(adapter.FormatAnthropic), canonical, map[string]struct{}{"b": {}})
	require.NoError(t, err)
	assert.Equal(t, string(body(toolA+","+toolC)), string(res.RequestBody))

	canonical, err = reg.DecodeRequestFor(body(toolA+","+toolB+","+toolC), adapter.FormatAnthropic)
	require.NoError(t, err)
	res, err = p.stripTools(body(toolA+","+toolB+","+toolC), string(adapter.FormatAnthropic), canonical, map[string]struct{}{"c": {}})
	require.NoError(t, err)
	decoded, err := reg.DecodeRequestFor(res.RequestBody, adapter.FormatAnthropic)
	require.NoError(t, err)
	require.Len(t, decoded.Tools, 2)
	assert.Contains(t, string(res.RequestBody), `"tools":[`+toolA+`,`)
	require.NotNil(t, decoded.Tools[1].Cache)
	assert.Equal(t, adapter.CacheTTL1h, decoded.Tools[1].Cache.TTL)
}

func TestStripToolsDropsToolsTheCanonicalDoesNotModel(t *testing.T) {
	t.Parallel()
	body := []byte(`{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"a"},{"type":"function","name":"b"},{"type":"mcp","server_label":"x","server_url":"https://x.example/mcp"}]}`)
	reg := adapter.NewRegistry()
	canonical, err := reg.DecodeRequestFor(body, adapter.FormatOpenAIResponses)
	require.NoError(t, err)
	res, err := New(nil, reg).stripTools(body, string(adapter.FormatOpenAIResponses), canonical, map[string]struct{}{"b": {}})
	require.NoError(t, err)
	assert.Equal(t, `{"model":"gpt-5","input":"hi","tools":[{"type":"function","name":"a"}]}`, string(res.RequestBody))
}
