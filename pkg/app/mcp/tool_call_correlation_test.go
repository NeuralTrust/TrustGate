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
	"context"
	"encoding/json"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestClientToolCallID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		meta string
		want string
	}{
		{name: "absent meta", meta: "", want: ""},
		{name: "null meta", meta: `null`, want: ""},
		{name: "empty object", meta: `{}`, want: ""},
		{name: "openai id", meta: `{"ai.neuraltrust/toolCallId":"call_abc123"}`, want: "call_abc123"},
		{name: "anthropic id", meta: `{"ai.neuraltrust/toolCallId":"toolu_01A-b_2"}`, want: "toolu_01A-b_2"},
		{
			name: "alongside spec keys",
			meta: `{"io.modelcontextprotocol/progressToken":7,"ai.neuraltrust/toolCallId":"call_1"}`,
			want: "call_1",
		},
		{name: "other key", meta: `{"toolCallId":"call_1"}`, want: ""},
		{name: "empty string", meta: `{"ai.neuraltrust/toolCallId":""}`, want: ""},
		{name: "not a string", meta: `{"ai.neuraltrust/toolCallId":42}`, want: ""},
		{name: "object", meta: `{"ai.neuraltrust/toolCallId":{"id":"call_1"}}`, want: ""},
		{name: "malformed meta", meta: `{not-json`, want: ""},
		{name: "meta is an array", meta: `["call_1"]`, want: ""},
		{name: "separator smuggled in", meta: `{"ai.neuraltrust/toolCallId":"a:b:c"}`, want: ""},
		{name: "glob smuggled in", meta: `{"ai.neuraltrust/toolCallId":"call_*"}`, want: ""},
		{name: "whitespace", meta: `{"ai.neuraltrust/toolCallId":"call 1"}`, want: ""},
		{
			name: "too long",
			meta: `{"ai.neuraltrust/toolCallId":"` + strings.Repeat("a", maxToolCallIDLen+1) + `"}`,
			want: "",
		},
		{
			name: "at the length bound",
			meta: `{"ai.neuraltrust/toolCallId":"` + strings.Repeat("a", maxToolCallIDLen) + `"}`,
			want: strings.Repeat("a", maxToolCallIDLen),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, clientToolCallID(json.RawMessage(tt.meta)))
		})
	}
}

func TestPluginRunner_ToolCallID_ReachesPlugins(t *testing.T) {
	t.Parallel()
	call := ToolCall{
		Exposed:          "send_email",
		Arguments:        json.RawMessage(testToolArgs),
		ClientToolCallID: "call_abc123",
	}

	exec := pluginmocks.NewExecutor(t)
	var captured appplugins.StageInput
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) { captured = in }).
		Return(&appplugins.StageOutcome{}, nil).Once()
	runner := NewPluginRunner(exec, discardLogger())

	_, err := runner.PreResponse(context.Background(), routableMCPConsumer(), call, json.RawMessage(testResult))
	require.NoError(t, err)
	require.NotNil(t, captured.Request)
	assert.Equal(t, "call_abc123", captured.Request.MCPToolCallID)
}

// The correlation id is the gateway's own accounting hint. It must not travel
// to the upstream tool, which never asked for the caller's conversation ids.
func TestPluginRunner_ToolCallID_StaysOutOfToolCallBody(t *testing.T) {
	t.Parallel()
	call := ToolCall{
		Exposed:          "send_email",
		Arguments:        json.RawMessage(testToolArgs),
		ClientToolCallID: "call_abc123",
	}

	exec := pluginmocks.NewExecutor(t)
	var captured appplugins.StageInput
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) { captured = in }).
		Return(&appplugins.StageOutcome{}, nil).Once()
	runner := NewPluginRunner(exec, discardLogger())

	_, err := runner.PreRequest(context.Background(), routableMCPConsumer(), call)
	require.NoError(t, err)
	require.NotNil(t, captured.Request)
	assert.NotContains(t, string(captured.Request.Body), "call_abc123")
	assert.JSONEq(t, `{"name":"send_email","arguments":`+testToolArgs+`}`, string(captured.Request.Body))
}

type capturingExecutor struct{ inputs []appplugins.StageInput }

func (c *capturingExecutor) RunStage(
	_ context.Context,
	in appplugins.StageInput,
) (*appplugins.StageOutcome, error) {
	c.inputs = append(c.inputs, in)
	return &appplugins.StageOutcome{}, nil
}

// The whole path a real tools/call takes: raw JSON-RPC params in, a correlation
// id on the request context every stage sees out.
func TestRPCDispatcher_CallTool_PropagatesToolCallIDFromMeta(t *testing.T) {
	tests := []struct {
		name   string
		params string
		want   string
	}{
		{
			name:   "with meta",
			params: `{"name":"run_query","arguments":{"q":"select 1"},"_meta":{"ai.neuraltrust/toolCallId":"call_abc123"}}`,
			want:   "call_abc123",
		},
		{
			name:   "without meta",
			params: `{"name":"run_query","arguments":{"q":"select 1"}}`,
			want:   "",
		},
		{
			name:   "unusable id",
			params: `{"name":"run_query","arguments":{"q":"select 1"},"_meta":{"ai.neuraltrust/toolCallId":"a:b"}}`,
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newBenchFixture(t, benchNoScope)
			exec := &capturingExecutor{}
			d := NewRPCDispatcher(
				&benchComposer{target: f.target, result: json.RawMessage(`{"content":[]}`)},
				NewPluginRunner(exec, discardLogger()),
				nil, nil, nil,
			)

			_, err := d.Dispatch(f.ctx(), f.rc, "", "tools/call", json.RawMessage(tt.params))
			require.NoError(t, err)

			require.Len(t, exec.inputs, 2)
			for _, in := range exec.inputs {
				require.NotNil(t, in.Request)
				assert.Equal(t, tt.want, in.Request.MCPToolCallID, "stage %s", in.Stage)
			}
		})
	}
}
