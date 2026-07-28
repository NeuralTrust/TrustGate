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

package promptcompression

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const openAIProvider = "openai"

func defaultSettings() map[string]any {
	return map[string]any{
		"compress_json":        true,
		"normalize_whitespace": true,
		"strip_ansi":           true,
	}
}

func reqCtx(provider, source string, body []byte) *infracontext.RequestContext {
	return &infracontext.RequestContext{Provider: provider, SourceFormat: source, Body: body}
}

func newEvent() *metrics.EventContext {
	tr := trace.New("", trace.Metadata{})
	span := tr.StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span)
}

func execInput(stage policy.Stage, mode policy.Mode, set map[string]any, req *infracontext.RequestContext, event *metrics.EventContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:   stage,
		Mode:    mode,
		Config:  policy.PluginConfig{Settings: set},
		Request: req,
		Event:   event,
	}
}

func openAIRequest(t *testing.T, system, user string) []byte {
	t.Helper()
	payload := map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	return body
}

func assertPassThrough(t *testing.T, res *appplugins.Result, err error) {
	t.Helper()
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.False(t, res.StopUpstream)
	assert.Nil(t, res.Body)
	assert.Nil(t, res.RequestBody)
}

func TestDescriptor(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	assert.Equal(t, "prompt_compression", p.Name())
	assert.Empty(t, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
	assert.ElementsMatch(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())
	assert.Equal(t, []appplugins.Protocol{appplugins.ProtocolLLM}, p.SupportedProtocols())
	assert.True(t, p.MutatesRequestBody())
	assert.False(t, p.MutatesResponseBody())
	assert.False(t, p.MutatesMetadata())
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	require.NoError(t, p.ValidateConfig(defaultSettings()))
	require.NoError(t, p.ValidateConfig(map[string]any{}), "empty settings must resolve to the catalog defaults")
	require.Error(t, p.ValidateConfig(map[string]any{
		"compress_json":        false,
		"normalize_whitespace": false,
		"strip_ansi":           false,
	}))
}

func TestExecuteCompressesJSONToolOutput(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	verboseJSON := "{\n  \"results\": [\n    {\"file\": \"a.go\", \"line\": 10},\n    {\"file\": \"b.go\", \"line\": 20}\n  ]\n}"
	body := openAIRequest(t, "You are helpful.", verboseJSON)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, defaultSettings(), reqCtx(openAIProvider, "", body), newEvent())

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.RequestBody, "expected a rewritten request body")
	assert.False(t, res.StopUpstream)
	assert.Less(t, len(res.RequestBody), len(body))

	creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, creq.Messages, 1)
	assert.Equal(t, "You are helpful.", creq.System, "untouched content must survive the round-trip")
	assert.JSONEq(t, verboseJSON, creq.Messages[0].Content, "compaction must preserve the JSON value")
	assert.Less(t, len(creq.Messages[0].Content), len(verboseJSON))
}

func TestExecuteObserveModeDoesNotRewrite(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	body := openAIRequest(t, "sys", "{\n  \"a\":   1\n}")
	event := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeObserve, defaultSettings(), reqCtx(openAIProvider, "", body), event)

	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteNoChangePassesThrough(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	body := openAIRequest(t, "short system", "plain prose question")
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, defaultSettings(), reqCtx(openAIProvider, "", body), newEvent())

	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteTargetRolesScopesCompression(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	verboseJSON := "{\n  \"a\":   1,\n  \"b\":   2\n}"
	body := openAIRequest(t, verboseJSON, verboseJSON)
	set := defaultSettings()
	set["target_roles"] = []any{"user"}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, "", body), newEvent())

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)

	creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, creq.Messages, 1)
	assert.Equal(t, verboseJSON, creq.System, "system prompt must stay untouched")
	assert.Less(t, len(creq.Messages[0].Content), len(verboseJSON), "user message must be compacted")
}

func TestExecuteInvalidBodyFailsOpen(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, defaultSettings(), reqCtx(openAIProvider, "", []byte("not json")), newEvent())

	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteMissingRequestFailsOpen(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, defaultSettings(), nil, newEvent())

	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteInvalidSettingsErrors(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	allOff := map[string]any{"compress_json": false, "normalize_whitespace": false, "strip_ansi": false}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, allOff, reqCtx(openAIProvider, "", []byte("{}")), newEvent())

	_, err := p.Execute(context.Background(), in)
	require.Error(t, err)
}

func TestExecuteBodyCapSkipsPipeline(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	verboseJSON := "{\n  \"a\":   1,\n  \"b\":   2\n}"
	body := openAIRequest(t, "sys", verboseJSON)
	set := defaultSettings()
	set["max_body_bytes"] = len(body) - 1
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, "", body), newEvent())

	res, err := p.Execute(context.Background(), in)
	assertPassThrough(t, res, err)
}

func TestExecuteCompressesOpenAIToolCallArguments(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	prettyArgs := "{\n  \"query\":   \"trustgate\",\n  \"limit\":   10\n}"
	prettyResult := "{\n  \"hits\": [\n    {\"id\": 1},\n    {\"id\": 2}\n  ]\n}"
	payload := map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": "search please"},
			{"role": "assistant", "content": nil, "tool_calls": []map[string]any{
				{"id": "call_1", "type": "function", "function": map[string]any{"name": "search", "arguments": prettyArgs}},
			}},
			{"role": "tool", "tool_call_id": "call_1", "content": prettyResult},
		},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, defaultSettings(), reqCtx(openAIProvider, "", body), newEvent())

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody, "expected a rewritten request body")
	assert.Less(t, len(res.RequestBody), len(body))

	creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, creq.Messages, 3)
	require.Len(t, creq.Messages[1].ToolCalls, 1)
	gotArgs := creq.Messages[1].ToolCalls[0].Arguments
	assert.JSONEq(t, prettyArgs, gotArgs, "compaction must preserve the arguments value")
	assert.Less(t, len(gotArgs), len(prettyArgs))
	assert.JSONEq(t, prettyResult, creq.Messages[2].Content, "compaction must preserve the tool result value")
	assert.Less(t, len(creq.Messages[2].Content), len(prettyResult))
}

func TestExecuteCompressesAnthropicToolUseInput(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	// The tool input is pretty-printed inside the wire body; building the body
	// by hand keeps json.Marshal from compacting it before the plugin runs.
	prettyArgs := `{"path":  "/tmp/x",  "recursive":  true}`
	body := []byte(`{"model":"claude-3","messages":[{"role":"user","content":"list files"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"ls","input":` + prettyArgs + `}]}],"max_tokens":100}`)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, defaultSettings(), reqCtx("anthropic", "", body), newEvent())

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody, "expected a rewritten request body")

	creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatAnthropic)
	require.NoError(t, err)
	var toolCall *adapter.CanonicalToolCall
	for i := range creq.Messages {
		if len(creq.Messages[i].ToolCalls) > 0 {
			toolCall = &creq.Messages[i].ToolCalls[0]
			break
		}
	}
	require.NotNil(t, toolCall, "tool call must survive the round-trip")
	assert.JSONEq(t, prettyArgs, toolCall.Arguments, "compaction must preserve the tool input value")
	assert.Less(t, len(toolCall.Arguments), len(prettyArgs))
}

func TestExecuteToolCallArgumentsRespectGates(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	prettyArgs := "{\n  \"q\":   \"x\"\n}"
	payload := map[string]any{
		"model": "gpt-4o",
		"messages": []map[string]any{
			{"role": "user", "content": "go"},
			{"role": "assistant", "content": nil, "tool_calls": []map[string]any{
				{"id": "call_1", "type": "function", "function": map[string]any{"name": "search", "arguments": prettyArgs}},
			}},
		},
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	t.Run("min_length skips short arguments", func(t *testing.T) {
		t.Parallel()
		set := defaultSettings()
		set["min_length"] = len(prettyArgs) + 1
		in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, "", body), newEvent())
		res, err := p.Execute(context.Background(), in)
		assertPassThrough(t, res, err)
	})

	t.Run("target_roles excludes assistant tool calls", func(t *testing.T) {
		t.Parallel()
		set := defaultSettings()
		set["target_roles"] = []any{"user"}
		in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, "", body), newEvent())
		res, err := p.Execute(context.Background(), in)
		assertPassThrough(t, res, err)
	})
}

func TestExecuteAnthropicSystemCompressed(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	verboseJSON := "{\n  \"policy\":   \"strict\",\n  \"rules\":   [1, 2, 3]\n}"
	payload := map[string]any{
		"model":      "claude-3",
		"system":     verboseJSON,
		"messages":   []map[string]any{{"role": "user", "content": "hi"}},
		"max_tokens": 100,
	}
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, defaultSettings(), reqCtx("anthropic", "", body), newEvent())

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)

	creq, err := adapter.NewRegistry().DecodeRequestFor(res.RequestBody, adapter.FormatAnthropic)
	require.NoError(t, err)
	assert.JSONEq(t, verboseJSON, creq.System)
	assert.Less(t, len(creq.System), len(verboseJSON))
}
