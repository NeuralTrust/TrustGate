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

package adapter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func chatEncoderFrames(t *testing.T, lines [][]byte) []json.RawMessage {
	t.Helper()
	var frames []json.RawMessage
	for _, line := range lines {
		if data, ok := bytes.CutPrefix(line, []byte("data: ")); ok {
			frames = append(frames, bytes.Clone(data))
		}
	}
	return frames
}

func TestOpenAIChatStreamEncoderFinishOrdering(t *testing.T) {
	for _, includeUsage := range []bool{false, true} {
		t.Run(map[bool]string{false: "without usage", true: "with usage"}[includeUsage], func(t *testing.T) {
			e := NewOpenAIChatStreamEncoder(includeUsage)
			first := &CanonicalStreamChunk{ID: "msg_1", Model: "claude", Role: "assistant",
				Usage: &CanonicalUsage{InputTokens: 9}, FinishReason: "stop"}
			lines := e.Content(first)
			firstFrames := chatEncoderFrames(t, lines)
			require.Len(t, firstFrames, 1)
			assert.NotContains(t, string(firstFrames[0]), "usage")
			assert.NotContains(t, string(firstFrames[0]), "finish_reason")
			assert.Equal(t, "stop", first.FinishReason)
			require.NotNil(t, first.Usage)
			lines = append(lines, e.Content(&CanonicalStreamChunk{Delta: "hello"})...)
			lines = append(lines, e.Finish(&CanonicalStreamChunk{FinishReason: "stop",
				Usage: &CanonicalUsage{InputTokens: 9, OutputTokens: 2, TotalTokens: 11}})...)
			frames := chatEncoderFrames(t, lines)
			want := 4
			if includeUsage {
				want++
			}
			require.Len(t, frames, want)
			assert.Equal(t, "[DONE]", string(frames[len(frames)-1]))
			for _, data := range frames[:len(frames)-1] {
				var frame openaiStreamChunk
				require.NoError(t, json.Unmarshal(data, &frame))
				assert.Equal(t, "msg_1", frame.ID)
				assert.Equal(t, "claude", frame.Model)
			}
			var finish openaiStreamChunk
			require.NoError(t, json.Unmarshal(frames[2], &finish))
			require.Len(t, finish.Choices, 1)
			require.NotNil(t, finish.Choices[0].FinishReason)
			assert.Equal(t, "stop", *finish.Choices[0].FinishReason)
			assert.Nil(t, finish.Usage)
			if includeUsage {
				var usage openaiStreamChunk
				require.NoError(t, json.Unmarshal(frames[3], &usage))
				assert.Empty(t, usage.Choices)
				assert.Contains(t, string(frames[3]), `"choices":[]`)
				assert.JSONEq(t, `{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}`,
					string(mustChatUsageJSON(t, usage.Usage)))
			}
			assert.Empty(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))
			assert.Empty(t, e.Content(&CanonicalStreamChunk{Delta: "late"}))
			assert.Empty(t, e.Abort("late failure"))
			assert.False(t, e.Aborted())
		})
	}
}

func mustChatUsageJSON(t *testing.T, usage *openaiUsage) []byte {
	t.Helper()
	require.NotNil(t, usage)
	data, err := json.Marshal(usage)
	require.NoError(t, err)
	return data
}

func TestOpenAIChatStreamEncoderPreservesToolAndReasoningDeltas(t *testing.T) {
	e := NewOpenAIChatStreamEncoder(false)
	frames := chatEncoderFrames(t, e.Content(&CanonicalStreamChunk{ID: "msg_2", Model: "claude",
		ReasoningDelta: "reason", ToolCallDeltas: []StreamToolCallDelta{
			{Index: 1, ID: "toolu_1", Name: "lookup", ArgumentsDelta: `{"city":`},
		}}))
	require.Len(t, frames, 1)
	var frame openaiStreamChunk
	require.NoError(t, json.Unmarshal(frames[0], &frame))
	require.Len(t, frame.Choices, 1)
	assert.Equal(t, "reason", frame.Choices[0].Delta.ReasoningContent)
	require.Len(t, frame.Choices[0].Delta.ToolCalls, 1)
	call := frame.Choices[0].Delta.ToolCalls[0]
	assert.Equal(t, 1, call.Index)
	assert.Equal(t, "toolu_1", call.ID)
	assert.Equal(t, "lookup", call.Function.Name)
	assert.Equal(t, `{"city":`, call.Function.Arguments)
}

func TestOpenAIChatStreamEncoderSynthesizesOnlyAbsentIdentity(t *testing.T) {
	e := NewOpenAIChatStreamEncoder(true)
	assert.Empty(t, e.Content(&CanonicalStreamChunk{Model: "selected-model"}))
	frames := chatEncoderFrames(t, e.Content(&CanonicalStreamChunk{Delta: "hello"}))
	frames = append(frames, chatEncoderFrames(t, e.Content(&CanonicalStreamChunk{ID: "late-id", Model: "late-model", Delta: "world"}))...)
	frames = append(frames, chatEncoderFrames(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))...)
	var id string
	for _, data := range frames[:len(frames)-1] {
		var frame openaiStreamChunk
		require.NoError(t, json.Unmarshal(data, &frame))
		assert.True(t, strings.HasPrefix(frame.ID, "chatcmpl-"))
		assert.Equal(t, "selected-model", frame.Model)
		if id == "" {
			id = frame.ID
		}
		assert.Equal(t, id, frame.ID)
	}
}

func TestOpenAIChatStreamEncoderAbortHasNoSuccessMarkers(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(map[bool]string{false: "before content", true: "after content"}[started], func(t *testing.T) {
			e := NewOpenAIChatStreamEncoder(true)
			if started {
				e.Content(&CanonicalStreamChunk{ID: "msg_3", Model: "claude", Delta: "hello"})
			}
			frames := chatEncoderFrames(t, e.Abort("upstream failed"))
			require.Len(t, frames, 1)
			assert.Contains(t, string(frames[0]), `"error"`)
			assert.NotContains(t, string(frames[0]), "finish_reason")
			assert.NotContains(t, string(frames[0]), "usage")
			assert.NotContains(t, string(frames[0]), "[DONE]")
			assert.True(t, e.Aborted())
			assert.Empty(t, e.Abort("again"))
			assert.Empty(t, e.Content(&CanonicalStreamChunk{Delta: "late"}))
			assert.Empty(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))
		})
	}
}

func TestOpenAIChatStreamEncoderRejectsFailedFinish(t *testing.T) {
	for _, reason := range []string{"", "error", "MALFORMED_FUNCTION_CALL"} {
		t.Run(reason, func(t *testing.T) {
			e := NewOpenAIChatStreamEncoder(true)
			frames := chatEncoderFrames(t, e.Finish(&CanonicalStreamChunk{FinishReason: reason}))
			require.Len(t, frames, 1)
			assert.Contains(t, string(frames[0]), `"error"`)
			assert.True(t, e.Aborted())
		})
	}
}

func TestOpenAIChatStreamEncoderRejectsUnencodableContent(t *testing.T) {
	e := NewOpenAIChatStreamEncoder(true)
	frames := chatEncoderFrames(t, e.Content(&CanonicalStreamChunk{Delta: "hello",
		ProviderExtensions: map[string]json.RawMessage{"x_groq": json.RawMessage(`invalid`)}}))
	require.Len(t, frames, 1)
	assert.Contains(t, string(frames[0]), `"error"`)
	assert.True(t, e.Aborted())
	assert.Empty(t, e.Finish(&CanonicalStreamChunk{FinishReason: "stop"}))
}

func TestOpenAIChatStreamEncoderRejectsUpstreamErrors(t *testing.T) {
	for _, finish := range []bool{false, true} {
		e := NewOpenAIChatStreamEncoder(true)
		chunk := &CanonicalStreamChunk{Delta: "hello", FinishReason: "stop",
			Usage: &CanonicalUsage{OutputTokens: 1}, UpstreamError: &UpstreamStreamError{}}
		var lines [][]byte
		if finish {
			lines = e.Finish(chunk)
		} else {
			lines = e.Content(chunk)
		}
		frames := chatEncoderFrames(t, lines)
		require.Len(t, frames, 1)
		assert.Contains(t, string(frames[0]), `"error"`)
		assert.NotContains(t, string(frames[0]), "[DONE]")
		assert.NotContains(t, string(frames[0]), "finish_reason")
		assert.True(t, e.Aborted())
	}
}

func TestOpenAIChatIncludesUsage(t *testing.T) {
	for _, test := range []struct {
		body string
		want bool
	}{
		{`{"stream_options":{"include_usage":true}}`, true},
		{`{"stream_options":{"include_usage":false}}`, false},
		{`{"stream_options":{}}`, false},
		{`{"stream_options":null}`, false},
		{`{}`, false},
		{`{"stream_options":{"include_usage":"true"}}`, false},
		{`not json`, false},
	} {
		assert.Equal(t, test.want, OpenAIChatIncludesUsage([]byte(test.body)), test.body)
	}
}
