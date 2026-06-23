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

package prompttemplate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeBodyErrors(t *testing.T) {
	t.Run("empty body rejected", func(t *testing.T) {
		_, err := decodeBody([]byte("   "))
		assert.Error(t, err)
	})

	t.Run("invalid json rejected", func(t *testing.T) {
		_, err := decodeBody([]byte("{not json"))
		assert.Error(t, err)
	})

	t.Run("non-string system falls back to messages shape", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"system":[{"type":"text"}],"messages":[{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		assert.False(t, rb.hasSystem)
		assert.True(t, rb.hasMessages)
	})

	t.Run("non-array messages marked opaque", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":"not-an-array"}`))
		require.NoError(t, err)
		assert.False(t, rb.hasMessages)
		assert.True(t, rb.messagesOpaque)
	})
}

func TestInjectSystemStringShape(t *testing.T) {
	t.Run("merge appends to existing system string", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"model":"gpt-4","system":"Be concise."}`))
		require.NoError(t, err)
		rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"model":"gpt-4","system":"Be concise.\n\nYou are support."}`, string(out))
	})

	t.Run("replace overwrites existing system string", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"system":"Be concise."}`))
		require.NoError(t, err)
		rb.injectSystem(onExistingReplace, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"system":"You are support."}`, string(out))
	})

	t.Run("merge with empty system string uses rendered content", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"system":""}`))
		require.NoError(t, err)
		rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"system":"You are support."}`, string(out))
	})
}

func TestInjectSystemMessagesShape(t *testing.T) {
	t.Run("merge appends to existing system message", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"system","content":"Be concise."},{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"system","content":"Be concise.\n\nYou are support."},{"role":"user","content":"hi"}]}`, string(out))
	})

	t.Run("replace overwrites existing system message", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"system","content":"Be concise."},{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		rb.injectSystem(onExistingReplace, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"system","content":"You are support."},{"role":"user","content":"hi"}]}`, string(out))
	})

	t.Run("insert at front when no system message present", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"system","content":"You are support."},{"role":"user","content":"hi"}]}`, string(out))
	})

	t.Run("non-system role inserts new message at front", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"system","content":"Be concise."},{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		rb.injectSystem(onExistingMerge, "developer", "Dev note.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"developer","content":"Dev note."},{"role":"system","content":"Be concise."},{"role":"user","content":"hi"}]}`, string(out))
	})
}

func TestInjectSystemPreservesMessageFields(t *testing.T) {
	t.Run("merge keeps tool_calls and array content verbatim", func(t *testing.T) {
		raw := []byte(`{"model":"gpt-4","messages":[` +
			`{"role":"system","content":"Be concise."},` +
			`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},` +
			`{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"http://x"}}],"name":"alice"}` +
			`]}`)
		rb, err := decodeBody(raw)
		require.NoError(t, err)
		rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)

		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		msgs, ok := got["messages"].([]any)
		require.True(t, ok)
		require.Len(t, msgs, 3)

		sys := msgs[0].(map[string]any)
		assert.Equal(t, "system", sys["role"])
		assert.Equal(t, "Be concise.\n\nYou are support.", sys["content"])

		assistant := msgs[1].(map[string]any)
		assert.Contains(t, assistant, "tool_calls")
		toolCalls := assistant["tool_calls"].([]any)
		assert.Equal(t, "call_1", toolCalls[0].(map[string]any)["id"])

		user := msgs[2].(map[string]any)
		assert.Equal(t, "alice", user["name"])
		_, isArray := user["content"].([]any)
		assert.True(t, isArray)
	})

	t.Run("insert keeps every existing message", func(t *testing.T) {
		raw := []byte(`{"messages":[` +
			`{"role":"user","content":"hi"},` +
			`{"role":"assistant","content":"hello","tool_call_id":"t1"}` +
			`]}`)
		rb, err := decodeBody(raw)
		require.NoError(t, err)
		rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[`+
			`{"role":"system","content":"You are support."},`+
			`{"role":"user","content":"hi"},`+
			`{"role":"assistant","content":"hello","tool_call_id":"t1"}`+
			`]}`, string(out))
	})

	t.Run("array-content system message merge inserts instead of corrupting", func(t *testing.T) {
		raw := []byte(`{"messages":[{"role":"system","content":[{"type":"text","text":"Be concise."}]}]}`)
		rb, err := decodeBody(raw)
		require.NoError(t, err)
		rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[`+
			`{"role":"system","content":"You are support."},`+
			`{"role":"system","content":[{"type":"text","text":"Be concise."}]}`+
			`]}`, string(out))
	})
}

func TestInjectSystemNonArrayMessagesUntouched(t *testing.T) {
	raw := []byte(`{"messages":"not-an-array","model":"gpt-4"}`)
	rb, err := decodeBody(raw)
	require.NoError(t, err)
	rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
	assert.False(t, rb.messagesDirty)
	out, err := rb.marshal()
	require.NoError(t, err)
	assert.JSONEq(t, string(raw), string(out))
}

func TestMarshalPreservesUnknownFields(t *testing.T) {
	raw := []byte(`{"model":"gpt-4","temperature":0.7,"messages":[{"role":"user","content":"hi"}]}`)
	rb, err := decodeBody(raw)
	require.NoError(t, err)
	rb.injectSystem(onExistingMerge, roleSystem, "You are support.")
	out, err := rb.marshal()
	require.NoError(t, err)
	assert.JSONEq(t, `{"model":"gpt-4","temperature":0.7,"messages":[{"role":"system","content":"You are support."},{"role":"user","content":"hi"}]}`, string(out))
}

func TestMarshalUntouchedBodyStable(t *testing.T) {
	raw := []byte(`{"model":"gpt-4","temperature":0.7,"messages":[{"role":"user","content":"hi"}]}`)
	rb, err := decodeBody(raw)
	require.NoError(t, err)
	out, err := rb.marshal()
	require.NoError(t, err)
	assert.JSONEq(t, string(raw), string(out))
}

func TestTakeProperties(t *testing.T) {
	t.Run("strips properties and decodes map", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"model":"gpt-4","properties":{"persona":"friendly","count":3},"messages":[{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		props, ok := rb.takeProperties()
		require.True(t, ok)
		assert.Equal(t, "friendly", props["persona"])
		assert.InEpsilon(t, float64(3), props["count"], 0.0001)
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`, string(out))
	})

	t.Run("absent properties returns false", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		_, ok := rb.takeProperties()
		assert.False(t, ok)
	})

	t.Run("non-object properties still stripped", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"properties":"oops","messages":[{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		_, ok := rb.takeProperties()
		assert.True(t, ok)
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"user","content":"hi"}]}`, string(out))
	})
}

func TestFindReferences(t *testing.T) {
	t.Run("scans message content", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":"{template://support-bot@stable}"}]}`))
		require.NoError(t, err)
		refs := rb.findReferences()
		require.Len(t, refs, 1)
		assert.Equal(t, "support-bot", refs[0].name)
		assert.Equal(t, "stable", refs[0].label)
	})

	t.Run("ignores top-level system string", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"system":"prefix {template://support-bot}","messages":[{"role":"user","content":"hi"}]}`))
		require.NoError(t, err)
		assert.Empty(t, rb.findReferences())
	})

	t.Run("multiple message references return all in order", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":"{template://first@a}"},{"role":"user","content":"{template://second@b}"}]}`))
		require.NoError(t, err)
		refs := rb.findReferences()
		require.Len(t, refs, 2)
		assert.Equal(t, "first", refs[0].name)
		assert.Equal(t, "second", refs[1].name)
	})

	t.Run("no reference returns empty", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":"hello"}]}`))
		require.NoError(t, err)
		assert.Empty(t, rb.findReferences())
	})

	t.Run("ignores non-string content", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"{template://x}"}]}]}`))
		require.NoError(t, err)
		assert.Empty(t, rb.findReferences())
	})
}

func TestReplaceMessages(t *testing.T) {
	t.Run("json array fragment replaces messages", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"model":"gpt-4","messages":[{"role":"user","content":"{template://x}"}]}`))
		require.NoError(t, err)
		require.NoError(t, rb.replaceMessages(`[{"role":"system","content":"You are a bot."},{"role":"user","content":"go"}]`))
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"model":"gpt-4","messages":[{"role":"system","content":"You are a bot."},{"role":"user","content":"go"}]}`, string(out))
	})

	t.Run("bare string wraps into single user message", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":"{template://x}"}]}`))
		require.NoError(t, err)
		require.NoError(t, rb.replaceMessages("You are a friendly bot."))
		out, err := rb.marshal()
		require.NoError(t, err)
		assert.JSONEq(t, `{"messages":[{"role":"user","content":"You are a friendly bot."}]}`, string(out))
	})

	t.Run("malformed array fragment errors", func(t *testing.T) {
		rb, err := decodeBody([]byte(`{"messages":[{"role":"user","content":"x"}]}`))
		require.NoError(t, err)
		assert.Error(t, rb.replaceMessages(`[{"role":`))
	})
}
