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
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeToolInput(t *testing.T) {
	t.Parallel()
	got, ok := NormalizeToolInput(`{"to":"bob@x.io","n":1e3,"s":"a\/b \"q\" <tag>"}`)
	require.True(t, ok)
	assert.Equal(t, `{"to":"bob@x.io","n":1e3,"s":"a/b \"q\" <tag>"}`, got, "strings are read, nothing else moves")
	_, ok = NormalizeToolInput(`{"to":"bob`)
	assert.False(t, ok)
}

func TestMaskToolInput(t *testing.T) {
	t.Parallel()
	t.Run("a value inside a string", func(t *testing.T) {
		t.Parallel()
		got, ok := MaskToolInput(`{"to":"bob@x.io","n":7}`, `{"to":"<EMAIL>","n":7}`)
		require.True(t, ok)
		assert.Equal(t, `{"to":"<EMAIL>","n":7}`, got, "no HTML escaping")
	})
	t.Run("what the policy writes is escaped as string content", func(t *testing.T) {
		t.Parallel()
		got, ok := MaskToolInput(`{"to":"bob@x.io"}`, `{"to":"["REDACTED"]"}`)
		require.True(t, ok)
		assert.JSONEq(t, `{"to":"[\"REDACTED\"]"}`, got)
	})
	t.Run("refused", func(t *testing.T) {
		t.Parallel()
		for name, c := range map[string][2]string{
			"a number":                {`{"p":4155550123}`, `{"p":<PHONE>}`},
			"a key":                   {`{"bob@x.io":1}`, `{"<EMAIL>":1}`},
			"a literal":               {`{"ok":true}`, `{"ok":false}`},
			"text added":              {`{"to":"bob"}`, `{"to":"bob and more"}`},
			"only spacing":            {`{"to": "bob"}`, `{"to":"bob"}`},
			"not changed":             {`{"to":"bob"}`, `{"to":"bob"}`},
			"input is not JSON":       {`{"to":"bob@x`, `{"to":"<M>`},
			"one copy of two is kept": {`{"a":"bob@x.io","b":"bob@x.io"}`, `{"a":"<E>","b":"bob@x.io"}`},
			"structure changed":       {`{"to":"bob@x.io"}`, `{"to":"<E>"},{"x":1}`},
			"a mask inside an escape": {`{"to":"a\nb"}`, `{"to":"a\xb"}`},
		} {
			_, ok := MaskToolInput(c[0], c[1])
			assert.False(t, ok, name)
		}
	})
	t.Run("a short value is changed where the policy changed it only", func(t *testing.T) {
		t.Parallel()
		got, ok := MaskToolInput(`{"a":"pin 42","n":42,"b":"x-42"}`, `{"a":"pin ##","n":42,"b":"x-42"}`)
		require.True(t, ok)
		assert.Equal(t, `{"a":"pin ##","n":42,"b":"x-42"}`, got)
	})
}

func frameWith(t *testing.T, eventType, payload string) []byte {
	t.Helper()
	var headers eventstream.Headers
	headers.Set(":message-type", eventstream.StringValue("event"))
	headers.Set(":event-type", eventstream.StringValue(eventType))
	headers.Set(":content-type", eventstream.StringValue("application/json"))
	var buf bytes.Buffer
	require.NoError(t, eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: headers, Payload: []byte(payload)}))
	return buf.Bytes()
}

func TestRewriteBedrockFrameToolInput(t *testing.T) {
	t.Parallel()
	t.Run("converse", func(t *testing.T) {
		t.Parallel()
		frame := frameWith(t, "contentBlockDelta", `{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"a\":"}}}`)
		in, ok := BedrockFrameToolInput(frame)
		require.True(t, ok)
		assert.Equal(t, `{"a":`, in)

		out, ok := RewriteBedrockFrameToolInput(frame, `{"a":"<E>"}`)
		require.True(t, ok)
		msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(out), nil)
		require.NoError(t, err, "valid prelude, length and checksums")
		assert.Equal(t, "contentBlockDelta", msg.Headers.Get(":event-type").String(), "headers are kept")
		assert.JSONEq(t, `{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"a\":\"<E>\"}"}}}`, string(msg.Payload))
		assert.Contains(t, string(msg.Payload), `<E>`, "no HTML escaping")
		in, ok = BedrockFrameToolInput(out)
		require.True(t, ok)
		assert.Equal(t, `{"a":"<E>"}`, in)
	})
	t.Run("anthropic invoke chunk", func(t *testing.T) {
		t.Parallel()
		inner := `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}`
		frame := frameWith(t, "chunk", `{"bytes":"`+base64.StdEncoding.EncodeToString([]byte(inner))+`"}`)
		out, ok := RewriteBedrockFrameToolInput(frame, "")
		require.True(t, ok)
		in, ok := BedrockFrameToolInput(out)
		require.True(t, ok)
		assert.Empty(t, in)
		assert.Contains(t, strings.Join(func() []string {
			var s []string
			for _, l := range BedrockFrameView(out) {
				s = append(s, string(l))
			}
			return s
		}(), ""), `"index":1`)
	})
	t.Run("a frame without tool input", func(t *testing.T) {
		t.Parallel()
		frame := frameWith(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"hi"}}`)
		_, ok := BedrockFrameToolInput(frame)
		assert.False(t, ok)
		_, ok = RewriteBedrockFrameToolInput(frame, "x")
		assert.False(t, ok)
	})
}

func TestToolInputWithAnUnpairedSurrogateIsNotRewritten(t *testing.T) {
	t.Parallel()
	input := `{"x":"\ud83d","to":"bob@x.io"}`
	got, ok := NormalizeToolInput(input)
	assert.False(t, ok)
	assert.Equal(t, input, got, "returned as it came")
	_, ok = MaskToolInput(input, `{"x":"\ud83d","to":"<E>"}`)
	assert.False(t, ok, "a mask would write the untouched string back as U+FFFD")
	paired, ok := NormalizeToolInput(`{"x":"😀"}`)
	assert.True(t, ok, "a valid pair is fine")
	assert.Equal(t, "{\"x\":\"\U0001F600\"}", paired)
}
