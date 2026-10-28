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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// regexChatGuard runs one secret-masking regex_replace policy under cfg.
func regexChatGuard(t *testing.T, cfg streamGuardConfig) *streamGuard {
	t.Helper()
	base := regexGuardFor(t, regexPolicy(regexSettings("secret", "[MASK]", nil)))
	return newStreamGuard(base.runner, adapter.NewRegistry(), adapter.FormatOpenAI, base.in, cfg, newGuardLogger())
}

func maskOne(args string) ([]adapter.StreamToolCallDelta, map[int]string) {
	return []adapter.StreamToolCallDelta{{Index: 0, ArgumentsDelta: args}}, map[int]string{0: args}
}

func TestRewriteChatToolCallArgumentsPreservesUnmodelledFields(t *testing.T) {
	t.Parallel()
	line := []byte(`data:{"id":"c1","top_extra":{"trace":"keep"},"choices":[{"index":0,"choice_extra":true,"delta":{"tool_calls":[{"index":0,"call_extra":{"keep":1},"function":{"arguments":"secret","name":"run_shell","function_extra":"keep"}}]}}]}`)
	deltas, replacements := maskOne("[MASK]")

	lines, ok := rewriteChatToolCallArguments([][]byte{line}, deltas, replacements)

	require.True(t, ok)
	require.Len(t, lines, 1)
	payload, ok := dataPayload(lines[0])
	require.True(t, ok)
	var chunk map[string]any
	require.NoError(t, json.Unmarshal(payload, &chunk))
	assert.Equal(t, map[string]any{"trace": "keep"}, chunk["top_extra"])
	choice := chunk["choices"].([]any)[0].(map[string]any)
	assert.Equal(t, true, choice["choice_extra"])
	call := choice["delta"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
	assert.Equal(t, map[string]any{"keep": float64(1)}, call["call_extra"])
	function := call["function"].(map[string]any)
	assert.Equal(t, "[MASK]", function["arguments"])
	assert.Equal(t, "keep", function["function_extra"])
}

func TestRewriteChatToolCallArgumentsRefusesWhatItCannotRewrite(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"null function":  `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":null}]}}]}`,
		"null custom":    `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"type":"custom","custom":null}]}}]}`,
		"index mismatch": `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"secret"}}]}}]}`,
		"extra call":     `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"secret"}},{"index":0,"function":{"arguments":"secret"}}]}}]}`,
		"no data line":   `event: message`,
		"no tool calls":  `data: {"choices":[{"index":0,"delta":{"content":"secret"}}]}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deltas, replacements := maskOne("[MASK]")
			lines, ok := rewriteChatToolCallArguments([][]byte{[]byte(line)}, deltas, replacements)
			assert.False(t, ok)
			assert.Nil(t, lines)
		})
	}
}

// "custom": null beside a function object is a function call, as the decoder
// reads it.
func TestRewriteChatToolCallArgumentsNullCustomIsAFunctionCall(t *testing.T) {
	t.Parallel()
	line := []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"custom":null,"function":{"arguments":"secret"}}]}}]}`)
	deltas, replacements := maskOne("[MASK]")

	lines, ok := rewriteChatToolCallArguments([][]byte{line}, deltas, replacements)

	require.True(t, ok)
	assert.Equal(t, []string{"[MASK]"}, argumentFragments(t, []string{string(lines[0])}, "function", "arguments"))
	assert.NotContains(t, string(lines[0]), "secret")
}

// A call whose first fragment already reached the client cannot be masked.
func TestRemaskChatToolCallsRefusesAReleasedDelta(t *testing.T) {
	t.Parallel()
	g := chatToolGuard(&toolGuardStub{}, adapter.FormatOpenAI, streamGuardConfig{holdChatTools: true})
	event := func(id, name, args string) *streamEvent {
		return &streamEvent{
			lines:     [][]byte{[]byte(chatToolDelta(t, 0, id, name, args))},
			unit:      unitText,
			toolCalls: []adapter.StreamToolCallDelta{{Index: 0, ID: id, Name: name, ArgumentsDelta: args}},
		}
	}
	released, held := event("call_1", "run_shell", `{"cmd":"sec`), event("", "", `ret"}`)
	heldLine := string(held.lines[0])
	g.produced = []*streamEvent{released, held}
	g.releasedIdx = 1
	g.tools.merge(released.toolCalls)
	g.tools.merge(held.toolCalls)
	g.inspectedTools = g.tools.calls()

	ok := g.remaskChatToolCalls([]adapter.CanonicalToolCall{{ID: "call_1", Name: "run_shell", Arguments: `{"cmd":"[MASK]"}`}})

	assert.False(t, ok)
	assert.Equal(t, adapter.MaskCauseReleasedInput, g.maskCause)
	assert.Equal(t, heldLine, string(held.lines[0]), "nothing is rewritten on a refusal")
	assert.Equal(t, `ret"}`, held.toolCalls[0].ArgumentsDelta)
}

func TestStreamGuard_RegexMasksToolCallsOnUnspacedDataLines(t *testing.T) {
	t.Parallel()
	g := regexGuard(t, streamGuardConfig{holdChatTools: true}, "secret", "[MASK]")
	lines := chatToolStream(singleCallDeltas(t, `{"command":"echo secret","note":"keep"}`)...)
	for i, line := range lines {
		lines[i] = strings.Replace(line, "data: ", "data:", 1)
	}

	run := runChatToolGuard(t, g, lines, nil)

	require.Nil(t, run.pe)
	require.False(t, g.wasCut(), "cause: %s", g.maskCause)
	assert.NotContains(t, strings.Join(run.out, "\n"), "secret")
	assert.Equal(t, `{"command":"echo [MASK]","note":"keep"}`,
		strings.Join(argumentFragments(t, run.out, "function", "arguments"), ""))
}

// Past max_accumulated_bytes the rules see only the tail of the arguments, so
// the rewrite cannot replace them whole and the stream is refused.
func TestStreamGuard_RegexRefusesWindowedToolCallArguments(t *testing.T) {
	t.Parallel()
	args := `{"note":"` + strings.Repeat("x", 60) + ` secret"}`
	g := regexChatGuard(t, streamGuardConfig{holdChatTools: true, maxAccumBytes: 40})

	run := runChatToolGuard(t, g, chatToolStream(singleCallDeltas(t, args)...), nil)

	assert.True(t, run.pe != nil || g.wasCut(), "the windowed call is refused")
	assert.Equal(t, adapter.MaskCauseNoWindow, g.maskCause)
	assert.NotContains(t, strings.Join(run.out, "\n"), "secret")
}

// Under the default cadence a short text preamble and the tool call after it
// are one held block; both are masked.
func TestStreamGuard_RegexMasksPreambleAndToolCallInOneBlock(t *testing.T) {
	t.Parallel()
	g := regexChatGuard(t, streamGuardConfig{holdChatTools: true})
	lines := chatToolStream(singleCallDeltas(t, `{"command":"echo secret"}`)...)
	lines[0] = strings.Replace(lines[0], "Let me check that.", "Let me check the secret.", 1)

	run := runChatToolGuard(t, g, lines, nil)

	require.Nil(t, run.pe)
	require.False(t, g.wasCut(), "cause: %s", g.maskCause)
	assert.NotContains(t, strings.Join(run.out, "\n"), "secret")
	assert.Equal(t, "Let me check the [MASK].", streamedText(t, adapter.FormatOpenAI, run.out))
	assert.Equal(t, `{"command":"echo [MASK]"}`,
		strings.Join(argumentFragments(t, run.out, "function", "arguments"), ""))
}

func TestStreamGuard_RegexToolOnlyMaskIsAFinding(t *testing.T) {
	t.Parallel()
	g := regexGuard(t, streamGuardConfig{holdChatTools: true}, "secret", "[MASK]")

	run := runChatToolGuard(t, g, chatToolStream(singleCallDeltas(t, `{"command":"echo secret"}`)...), nil)

	require.Nil(t, run.pe)
	require.False(t, g.wasCut())
	require.NotEmpty(t, g.findings, "the stream reports the rule that masked the arguments")
	for _, f := range g.findings {
		assert.NotEmpty(t, f.Fingerprint)
	}
}
