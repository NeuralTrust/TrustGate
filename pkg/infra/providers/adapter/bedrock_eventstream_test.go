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
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encodeTestFrame(t *testing.T, messageType, eventType string, payload []byte) []byte {
	t.Helper()
	var headers eventstream.Headers
	headers.Set(":message-type", eventstream.StringValue(messageType))
	if messageType == "exception" {
		headers.Set(":exception-type", eventstream.StringValue(eventType))
	} else {
		headers.Set(":event-type", eventstream.StringValue(eventType))
	}
	headers.Set(":content-type", eventstream.StringValue("application/json"))
	var buf bytes.Buffer
	require.NoError(t, eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: headers, Payload: payload}))
	return buf.Bytes()
}

func TestReadBedrockFrame_RoundTripsBytesExactly(t *testing.T) {
	t.Parallel()
	first := encodeTestFrame(t, "event", "contentBlockDelta", []byte(`{"contentBlockIndex":0,"delta":{"text":"hi"}}`))
	second := encodeTestFrame(t, "event", "messageStop", []byte(`{"stopReason":"end_turn"}`))
	r := bytes.NewReader(append(bytes.Clone(first), second...))

	got1, err := ReadBedrockFrame(r, BedrockFrameMaxBytes)
	require.NoError(t, err)
	assert.Equal(t, first, got1)
	got2, err := ReadBedrockFrame(r, BedrockFrameMaxBytes)
	require.NoError(t, err)
	assert.Equal(t, second, got2)
	_, err = ReadBedrockFrame(r, BedrockFrameMaxBytes)
	assert.ErrorIs(t, err, io.EOF)
}

func TestReadBedrockFrame_RejectsBadFrames(t *testing.T) {
	t.Parallel()
	frame := encodeTestFrame(t, "event", "messageStop", []byte(`{"stopReason":"end_turn"}`))

	t.Run("oversize frame", func(t *testing.T) {
		t.Parallel()
		_, err := ReadBedrockFrame(bytes.NewReader(frame), len(frame)-1)
		assert.ErrorIs(t, err, ErrBedrockFrameTooLarge)
	})
	t.Run("frame at the limit", func(t *testing.T) {
		t.Parallel()
		got, err := ReadBedrockFrame(bytes.NewReader(frame), len(frame))
		require.NoError(t, err)
		assert.Equal(t, frame, got)
	})
	t.Run("truncated in the body", func(t *testing.T) {
		t.Parallel()
		_, err := ReadBedrockFrame(bytes.NewReader(frame[:len(frame)-3]), BedrockFrameMaxBytes)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("truncated in the prelude", func(t *testing.T) {
		t.Parallel()
		_, err := ReadBedrockFrame(bytes.NewReader(frame[:5]), BedrockFrameMaxBytes)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("declared length below the minimum", func(t *testing.T) {
		t.Parallel()
		bad := make([]byte, 16)
		binary.BigEndian.PutUint32(bad[:4], 8)
		_, err := ReadBedrockFrame(bytes.NewReader(bad), BedrockFrameMaxBytes)
		assert.ErrorIs(t, err, ErrBedrockFrameMalformed)
	})
	t.Run("huge declared length is refused before allocating", func(t *testing.T) {
		t.Parallel()
		bad := make([]byte, 16)
		binary.BigEndian.PutUint32(bad[:4], 0xFFFFFFFF)
		_, err := ReadBedrockFrame(bytes.NewReader(bad), BedrockFrameMaxBytes)
		assert.ErrorIs(t, err, ErrBedrockFrameTooLarge)
	})
}

func TestBedrockFrameView_ConverseEvents(t *testing.T) {
	t.Parallel()
	cases := []struct {
		eventType string
		payload   string
		want      string
	}{
		{"messageStart", `{"role":"assistant"}`, `data: {"messageStart":{"role":"assistant"}}`},
		{"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Hello"}}`,
			`data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Hello"}}}`},
		{"messageStop", `{"stopReason":"end_turn"}`, `data: {"messageStop":{"stopReason":"end_turn"}}`},
		{"metadata", `{"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13},"metrics":{"latencyMs":120}}`,
			`data: {"metadata":{"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13},"metrics":{"latencyMs":120}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			t.Parallel()
			lines := BedrockFrameView(encodeTestFrame(t, "event", tc.eventType, []byte(tc.payload)))
			require.Len(t, lines, 1)
			assert.Equal(t, tc.want, string(lines[0]))
		})
	}
}

func TestBedrockFrameView_FeedsTheConverseDecoder(t *testing.T) {
	t.Parallel()
	view := func(eventType, payload string) []byte {
		lines := BedrockFrameView(encodeTestFrame(t, "event", eventType, []byte(payload)))
		require.Len(t, lines, 1)
		return bytes.TrimPrefix(lines[0], []byte("data: "))
	}
	a := &BedrockAdapter{}

	chunk, err := a.DecodeStreamChunk(view("contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Hello"}}`))
	require.NoError(t, err)
	require.NotNil(t, chunk)
	assert.Equal(t, "Hello", chunk.Delta)

	chunk, err = a.DecodeStreamChunk(view("metadata", `{"usage":{"inputTokens":9,"outputTokens":4,"totalTokens":13}}`))
	require.NoError(t, err)
	require.NotNil(t, chunk)
	require.NotNil(t, chunk.Usage)
	assert.Equal(t, 9, chunk.Usage.InputTokens)
	assert.Equal(t, 4, chunk.Usage.OutputTokens)
}

func TestBedrockFrameView_InvokeChunkCarriesTheModelJSON(t *testing.T) {
	t.Parallel()
	inner := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`
	payload := `{"bytes":"` + base64.StdEncoding.EncodeToString([]byte(inner)) + `"}`
	lines := BedrockFrameView(encodeTestFrame(t, "event", "chunk", []byte(payload)))
	require.Len(t, lines, 1)
	assert.Equal(t, "data: "+inner, string(lines[0]))
}

func TestBedrockFrameView_NoLines(t *testing.T) {
	t.Parallel()
	valid := encodeTestFrame(t, "event", "messageStop", []byte(`{"stopReason":"end_turn"}`))
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)-1] ^= 0xFF

	cases := map[string][]byte{
		"exception frame":     encodeTestFrame(t, "exception", "throttlingException", []byte(`{"message":"slow down"}`)),
		"failed checksum":     corrupt,
		"not json payload":    encodeTestFrame(t, "event", "messageStop", []byte(`not json`)),
		"empty invoke chunk":  encodeTestFrame(t, "event", "chunk", []byte(`{"bytes":""}`)),
		"garbage":             []byte("not a frame at all"),
		"nil":                 nil,
		"invoke chunk no key": encodeTestFrame(t, "event", "chunk", []byte(`{}`)),
	}
	for name, raw := range cases {
		assert.Empty(t, BedrockFrameView(raw), name)
	}
}

func TestBedrockExceptionFrame_DecodesWithTheSDKDecoder(t *testing.T) {
	t.Parallel()
	raw := BedrockExceptionFrame("internalServerException", "upstream stream terminated unexpectedly")
	require.NotEmpty(t, raw)

	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(raw), nil)
	require.NoError(t, err)
	assert.Equal(t, "exception", msg.Headers.Get(":message-type").String())
	assert.Equal(t, "internalServerException", msg.Headers.Get(":exception-type").String())
	assert.JSONEq(t, `{"message":"upstream stream terminated unexpectedly"}`, string(msg.Payload))

	got, err := ReadBedrockFrame(bytes.NewReader(raw), BedrockFrameMaxBytes)
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

func TestBedrockUsageFromHeaders(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set("X-Amzn-Bedrock-Input-Token-Count", "11")
	h.Set("X-Amzn-Bedrock-Output-Token-Count", "7")
	usage := BedrockUsageFromHeaders(h)
	require.NotNil(t, usage)
	assert.Equal(t, 11, usage.InputTokens)
	assert.Equal(t, 7, usage.OutputTokens)
	assert.Equal(t, 18, usage.TotalTokens)

	assert.Nil(t, BedrockUsageFromHeaders(http.Header{}))
	h.Set("X-Amzn-Bedrock-Input-Token-Count", "not a number")
	h.Del("X-Amzn-Bedrock-Output-Token-Count")
	assert.Nil(t, BedrockUsageFromHeaders(h))
}

func TestBedrockUsageFromHeaders_CacheBuckets(t *testing.T) {
	t.Parallel()
	h := http.Header{}
	h.Set("X-Amzn-Bedrock-Input-Token-Count", "10")
	h.Set("X-Amzn-Bedrock-Output-Token-Count", "5")
	h.Set("X-Amzn-Bedrock-Cache-Read-Input-Token-Count", "100")
	h.Set("X-Amzn-Bedrock-Cache-Write-Input-Token-Count", "20")
	u := BedrockUsageFromHeaders(h)
	require.NotNil(t, u)
	assert.Equal(t, 130, u.InputTokens)
	assert.Equal(t, 100, u.CachedInputTokens)
	assert.Equal(t, 20, u.CacheWriteInputTokens)
	assert.Equal(t, 5, u.OutputTokens)
	assert.Equal(t, 135, u.TotalTokens)
}
