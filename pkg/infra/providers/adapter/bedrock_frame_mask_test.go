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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewriteBedrockFrameText_ConverseEvent(t *testing.T) {
	t.Parallel()
	frame := encodeTestFrame(t, "event", "contentBlockDelta",
		[]byte(`{"contentBlockIndex":3,"delta":{"text":"mail bob@x.io now"},"extra":{"n":1e-7}}`))

	got, ok := RewriteBedrockFrameText(frame, "mail bob@x.io now", "mail <EMAIL> now")
	require.True(t, ok)
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(got), nil)
	require.NoError(t, err, "length and both checksums are valid")
	orig, err := eventstream.NewDecoder().Decode(bytes.NewReader(frame), nil)
	require.NoError(t, err)
	assert.Equal(t, orig.Headers, msg.Headers, "the same headers")
	assert.JSONEq(t, `{"contentBlockIndex":3,"delta":{"text":"mail <EMAIL> now"},"extra":{"n":1e-7}}`, string(msg.Payload))
	assert.Contains(t, string(msg.Payload), "<EMAIL>", "no HTML escaping")
	assert.Contains(t, string(msg.Payload), "1e-7", "other values keep their literal form")
	assert.NotEqual(t, frame, got)
}

func TestRewriteBedrockFrameText_InvokeChunk(t *testing.T) {
	t.Parallel()
	inner := `{"outputText":"mail bob@x.io","index":0,"totalOutputTextTokenCount":6}`
	frame := encodeTestFrame(t, "event", "chunk", []byte(`{"bytes":"`+base64.StdEncoding.EncodeToString([]byte(inner))+`"}`))

	got, ok := RewriteBedrockFrameText(frame, "mail bob@x.io", "mail <EMAIL>")
	require.True(t, ok)
	lines := BedrockFrameView(got)
	require.Len(t, lines, 1)
	assert.JSONEq(t, `{"outputText":"mail <EMAIL>","index":0,"totalOutputTextTokenCount":6}`, string(bytes.TrimPrefix(lines[0], []byte("data: "))))
}

func TestRewriteBedrockFrameText_Refusals(t *testing.T) {
	t.Parallel()
	event := encodeTestFrame(t, "event", "contentBlockDelta", []byte(`{"delta":{"text":"hello"}}`))
	for name, c := range map[string]struct {
		frame    []byte
		old, new string
	}{
		"text not in the frame": {event, "absent", "x"},
		"empty original":        {event, "", "x"},
		"not a frame":           {[]byte("garbage"), "hello", "x"},
		"an exception frame":    {BedrockExceptionFrame("throttlingException", "hello"), "hello", "x"},
		"chunk with bad base64": {encodeTestFrame(t, "event", "chunk", []byte(`{"bytes":"!!"}`)), "hello", "x"},
		"payload not an object": {encodeTestFrame(t, "event", "chunk", []byte(`[1]`)), "hello", "x"},
	} {
		_, ok := RewriteBedrockFrameText(c.frame, c.old, c.new)
		assert.False(t, ok, name)
	}
}

func TestBedrockFrameHolds(t *testing.T) {
	t.Parallel()
	converse := encodeTestFrame(t, "event", "contentBlockDelta", []byte(`{"delta":{"text":"a"},"note":"bob@x.io"}`))
	assert.True(t, BedrockFrameHolds(converse, "bob@x.io"), "found in a field the view does not read")
	assert.False(t, BedrockFrameHolds(converse, "carol@x.io"))

	chunk := encodeTestFrame(t, "event", "chunk", []byte(`{"bytes":"`+base64.StdEncoding.EncodeToString([]byte(`{"x":"bob@x.io"}`))+`"}`))
	assert.True(t, BedrockFrameHolds(chunk, "bob@x.io"), "found inside the base64 JSON of a chunk")
	assert.True(t, BedrockFrameHolds([]byte("garbage"), "bob"), "a frame that cannot be read is not shown to be clean")
}

func TestBedrockFrameText(t *testing.T) {
	t.Parallel()
	frame := encodeTestFrame(t, "event", "contentBlockDelta", []byte(`{"delta":{"text":"hello"}}`))
	assert.Equal(t, "hello", BedrockFrameText(frame))
	assert.Empty(t, BedrockFrameText([]byte("garbage")))
}

func TestBedrockFrameHolds_DecodesEscapesAndSkipsPadding(t *testing.T) {
	t.Parallel()
	esc := encodeTestFrame(t, "event", "contentBlockDelta",
		[]byte(`{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"to\":\"john\\u0040x.com\"}"}}}`))
	assert.True(t, BedrockFrameHolds(esc, "john@x.com"), "an escaped @ inside a tool input fragment is found")

	inner := `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"to\":\"john\\u0040x.com\"}"}}`
	chunk := encodeTestFrame(t, "event", "chunk", []byte(`{"bytes":"`+base64.StdEncoding.EncodeToString([]byte(inner))+`"}`))
	assert.True(t, BedrockFrameHolds(chunk, "john@x.com"), "and inside the JSON of an invoke chunk")

	padded := encodeTestFrame(t, "event", "contentBlockDelta",
		[]byte(`{"contentBlockIndex":0,"delta":{"text":"[NAME] says hi"},"p":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"}`))
	assert.False(t, BedrockFrameHolds(padded, "nop"), "Bedrock's random padding is not the stream's text")
	assert.False(t, BedrockFrameHolds(padded, "Jkl"))
	assert.True(t, BedrockFrameHolds(padded, "says hi"))
}

func TestLooseJSONUnescape(t *testing.T) {
	t.Parallel()
	assert.Equal(t, `{"to":"john@x.com"}`, LooseJSONUnescape(`{\"to\":\"john@x.com\"}`))
	assert.Equal(t, "a\nb", LooseJSONUnescape(`a\nb`))
	assert.Equal(t, "😀", LooseJSONUnescape(`😀`))
	assert.Equal(t, `plain`, LooseJSONUnescape(`plain`))
	assert.Equal(t, `\u00zz`, LooseJSONUnescape(`\u00zz`), "a broken escape is left alone")
	assert.True(t, StringHolds(`{\\\"to\\\":\\\"john\\u0040x.com\\\"}`, "john@x.com"), "an escape inside an escape is undone too")
}
