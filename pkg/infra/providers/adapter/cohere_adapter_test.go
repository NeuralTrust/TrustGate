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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCohereAdapter_RoundtripRequest(t *testing.T) {
	input := `{
		"model": "command-r-plus",
		"messages": [{"role": "user", "content": "Hello"}],
		"max_tokens": 100,
		"temperature": 0.7
	}`

	a := &CohereAdapter{}
	canonical, err := a.DecodeRequest([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "command-r-plus", canonical.Model)
	assert.Len(t, canonical.Messages, 1)

	encoded, err := a.EncodeRequest(canonical)
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal(encoded, &result))
	assert.Equal(t, "command-r-plus", result["model"])
}

func TestCohereAdapter_OpenAIToCohereCrossFormat(t *testing.T) {
	reg := NewRegistry()
	openaiReq := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`

	out, err := reg.AdaptRequest([]byte(openaiReq), FormatOpenAI, FormatCohere)
	require.NoError(t, err)

	var cohereReq map[string]any
	require.NoError(t, json.Unmarshal(out, &cohereReq))
	assert.Equal(t, "gpt-4", cohereReq["model"])
	msgs := cohereReq["messages"].([]any)
	assert.Len(t, msgs, 1)
}

func TestCohereAdapter_StreamChunkContentDelta(t *testing.T) {
	a := &CohereAdapter{}
	chunk := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"hi"}}}}`)

	got, err := a.DecodeStreamChunk(chunk)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "hi", got.Delta)
}

func TestCohereEmbedAdapter_OpenAIToCohere(t *testing.T) {
	reg := NewRegistry()
	openaiReq := `{"model":"embed-english-v3.0","input":["hello","world"]}`

	out, err := AdaptEmbeddingRequest(reg, []byte(openaiReq), FormatOpenAIEmbeddings, FormatCohereEmbed)
	require.NoError(t, err)

	var cohereReq map[string]any
	require.NoError(t, json.Unmarshal(out, &cohereReq))
	assert.Equal(t, "embed-english-v3.0", cohereReq["model"])
	assert.Equal(t, []any{"hello", "world"}, cohereReq["texts"])
}

func TestCohereRerankAdapter_DecodeRequest_Model(t *testing.T) {
	a := &CohereRerankAdapter{}
	body := []byte(`{"model":"rerank-english-v3.0","query":"q","documents":["a"]}`)

	got, err := a.DecodeRequest(body)
	require.NoError(t, err)
	assert.Equal(t, "rerank-english-v3.0", got.Model)
}

func TestCohere_DecodeStreamChunk_SkipsThinking(t *testing.T) {
	a := &CohereAdapter{}
	thinking := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"thinking","thinking":"private"}}}}`)
	chunk, err := a.DecodeStreamChunk(thinking)
	require.NoError(t, err)
	assert.Nil(t, chunk)

	text := []byte(`{"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"hello"}}}}`)
	chunk, err = a.DecodeStreamChunk(text)
	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, "hello", chunk.Delta)
}

func encodeCohereStream(t *testing.T, chunks []*CanonicalStreamChunk) []string {
	t.Helper()
	a := &CohereAdapter{}
	var got []string
	for _, chunk := range chunks {
		lines, err := a.EncodeStreamChunk(chunk)
		require.NoError(t, err)
		got = append(got, bytesLinesToStrings(lines)...)
	}
	return got
}

// message-end is the whole cut signal on Cohere: the streamed-response union
// has no error member, so StreamBlockedEvent falls through to the OpenAI
// default and never reaches a Cohere client. A cut that says COMPLETE here is
// therefore a clean ending as far as the SDK can tell — and so is one that
// says ERROR without delta.error, since no SDK branches on the enum member.
// The last case pins the untouched shape of a normal finish.
func TestCohereEncodeStreamChunk_CutTerminatorGolden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		chunks []*CanonicalStreamChunk
		want   []string
	}{
		{
			name: "cut after partial text",
			chunks: []*CanonicalStreamChunk{
				{Delta: "Here is the "},
				{Delta: "recipe"},
				{FinishReason: "content_filter"},
			},
			want: []string{
				"event: content-delta",
				`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"Here is the "}}}}`,
				"",
				"event: content-delta",
				`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"recipe"}}}}`,
				"",
				"event: message-end",
				`data: {"type":"message-end","delta":{"finish_reason":"ERROR",` +
					`"error":"response blocked by content filter"}}`,
				"",
			},
		},
		{
			name: "cut carrying the usage of the stream it ends",
			chunks: []*CanonicalStreamChunk{
				{FinishReason: "content_filter", Usage: newCanonicalUsage(11, 7, 0)},
			},
			want: []string{
				"event: message-end",
				`data: {"type":"message-end","delta":{"finish_reason":"ERROR",` +
					`"error":"response blocked by content filter",` +
					`"usage":{"tokens":{"input_tokens":11,"output_tokens":7}}}}`,
				"",
			},
		},
		{
			// An OpenAI-family upstream with include_usage sends the finish
			// reason and the usage in two chunks. The trailing usage-only one
			// must not assert a second, contradicting finish reason: the client
			// reads the last message-end it receives.
			name: "cut whose usage arrives in a separate chunk",
			chunks: []*CanonicalStreamChunk{
				{Delta: "Here is the "},
				{FinishReason: "content_filter"},
				{Usage: newCanonicalUsage(11, 7, 0)},
			},
			want: []string{
				"event: content-delta",
				`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"Here is the "}}}}`,
				"",
				"event: message-end",
				`data: {"type":"message-end","delta":{"finish_reason":"ERROR",` +
					`"error":"response blocked by content filter"}}`,
				"",
				"event: message-end",
				`data: {"type":"message-end","delta":{"usage":{"tokens":{"input_tokens":11,"output_tokens":7}}}}`,
				"",
			},
		},
		{
			name: "normal finish",
			chunks: []*CanonicalStreamChunk{
				{Delta: "Here is the "},
				{Delta: "recipe"},
				{FinishReason: "stop"},
			},
			want: []string{
				"event: content-delta",
				`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"Here is the "}}}}`,
				"",
				"event: content-delta",
				`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"recipe"}}}}`,
				"",
				"event: message-end",
				`data: {"type":"message-end","delta":{"finish_reason":"COMPLETE"}}`,
				"",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, encodeCohereStream(t, tc.chunks))
		})
	}
}

// Both encoders read the same mapping, so a cut cannot be ERROR on the stream
// and COMPLETE on the buffered body. The two diverge on one input only: a
// buffered response carries exactly one finish_reason and has to say something,
// while a stream chunk with no finish reason is a trailing usage-only event and
// must not claim the response ended.
func TestCohereFinishReason_BufferedAndStreamedAgree(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		finishReason string
		wantBuffered string
		wantStreamed string
	}{
		{name: "stop", finishReason: "stop", wantBuffered: "COMPLETE", wantStreamed: "COMPLETE"},
		{name: "length", finishReason: "length", wantBuffered: "MAX_TOKENS", wantStreamed: "MAX_TOKENS"},
		{name: "tool calls", finishReason: "tool_calls", wantBuffered: "TOOL_CALL", wantStreamed: "TOOL_CALL"},
		{name: "content filter", finishReason: "content_filter", wantBuffered: "ERROR", wantStreamed: "ERROR"},
		{name: "upstream refusal", finishReason: "refusal", wantBuffered: "ERROR", wantStreamed: "ERROR"},
		{name: "empty", finishReason: "", wantBuffered: "COMPLETE", wantStreamed: ""},
		{name: "unrecognised", finishReason: "something_else", wantBuffered: "COMPLETE", wantStreamed: "COMPLETE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := &CohereAdapter{}

			body, err := a.EncodeResponse(&CanonicalResponse{
				ID: "msg_1", Model: "command-a", Content: "hi", FinishReason: tc.finishReason,
			})
			require.NoError(t, err)
			var buffered cohereResponse
			require.NoError(t, json.Unmarshal(body, &buffered))
			assert.Equal(t, tc.wantBuffered, buffered.FinishReason, "buffered")

			lines, err := a.EncodeStreamChunk(&CanonicalStreamChunk{FinishReason: tc.finishReason, Usage: newCanonicalUsage(1, 1, 0)})
			require.NoError(t, err)
			require.Len(t, lines, 3)
			var event cohereStreamEvent
			require.NoError(t, json.Unmarshal(bytes.TrimPrefix(lines[1], []byte("data: ")), &event))
			var delta cohereMessageEndDelta
			require.NoError(t, json.Unmarshal(event.Delta, &delta))
			assert.Equal(t, tc.wantStreamed, delta.FinishReason, "streamed")
		})
	}
}

// ChatFinishReason really does include ERROR, but no Cohere SDK in Python, TS
// or Go branches on it — the member appears only at its own declaration, and
// v2/raw_client.py ignores finish_reason outright. delta.error is the only
// field on message-end a client is given a reason to read, so the cut has to
// fill it and nothing else may.
func TestCohereEncodeStreamChunk_OnlyACutCarriesDeltaError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		finishReason string
		wantError    string
	}{
		{name: "content filter", finishReason: "content_filter", wantError: "response blocked by content filter"},
		{name: "upstream refusal", finishReason: "refusal", wantError: "response blocked by content filter"},
		{name: "stop", finishReason: "stop"},
		{name: "length", finishReason: "length"},
		{name: "tool calls", finishReason: "tool_calls"},
		{name: "unrecognised", finishReason: "something_else"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lines, err := (&CohereAdapter{}).EncodeStreamChunk(
				&CanonicalStreamChunk{FinishReason: tc.finishReason})
			require.NoError(t, err)
			require.Len(t, lines, 3)
			var event cohereStreamEvent
			require.NoError(t, json.Unmarshal(bytes.TrimPrefix(lines[1], []byte("data: ")), &event))
			var delta cohereMessageEndDelta
			require.NoError(t, json.Unmarshal(event.Delta, &delta))
			assert.Equal(t, tc.wantError, delta.Error)
			if tc.wantError == "" {
				assert.NotContains(t, string(lines[1]), `"error"`)
			}
		})
	}
}

// A trailing usage-only message-end is not a cut and must not repeat the
// error, any more than it repeats the finish reason.
func TestCohereEncodeStreamChunk_UsageOnlyCarriesNoError(t *testing.T) {
	t.Parallel()
	lines, err := (&CohereAdapter{}).EncodeStreamChunk(
		&CanonicalStreamChunk{Usage: newCanonicalUsage(11, 7, 0)})
	require.NoError(t, err)
	require.Len(t, lines, 3)
	assert.Equal(t,
		`data: {"type":"message-end","delta":{"usage":{"tokens":{"input_tokens":11,"output_tokens":7}}}}`,
		string(lines[1]))
}
