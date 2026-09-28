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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func legacyCall(t *testing.T, messages string) LegacyFunctionCall {
	t.Helper()
	ad, err := NewRegistry().GetAdapter(FormatOpenAI)
	require.NoError(t, err)
	calls := ExecutedLegacyFunctionCalls(ad, []byte(`{"model":"m","messages":[`+messages+`],"functions":[{"name":"get_weather"}]}`))
	require.Len(t, calls, 1, messages)
	assert.Equal(t, "get_weather", calls[0].Name)
	return calls[0]
}

func TestExecutedLegacyFunctionCallsIDsFollowTheConversation(t *testing.T) {
	t.Parallel()
	const call = `{"role":"assistant","content":null,"function_call":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}`
	const answer = `{"role":"function","name":"get_weather","content":"sunny"}`
	first := legacyCall(t, `{"role":"system","content":"s"},{"role":"user","content":"weather in Paris?"},`+call+`,`+answer)

	t.Run("two conversations with the same call at the same position", func(t *testing.T) {
		t.Parallel()
		other := legacyCall(t, `{"role":"system","content":"s"},{"role":"user","content":"another chat, Paris weather"},`+call+`,`+answer)
		assert.NotEqual(t, first.ID, other.ID)
	})
	t.Run("the conversation goes on", func(t *testing.T) {
		t.Parallel()
		later := legacyCall(t, `{"role":"system", "content":"s"},{"role":"user","content":"weather in Paris?"},`+call+`,`+answer+
			`,{"role":"assistant","content":"It is sunny."},{"role":"user","content":"thanks"}`)
		assert.Equal(t, first.ID, later.ID, "whitespace and later turns keep the id")
	})
	t.Run("a trimmed history", func(t *testing.T) {
		t.Parallel()
		trimmed := legacyCall(t, `{"role":"user","content":"weather in Paris?"},`+call+`,`+answer)
		assert.NotEqual(t, first.ID, trimmed.ID, "a prefix the client cut is another conversation: the call counts again rather than never")
	})
	t.Run("a message that does not decode", func(t *testing.T) {
		t.Parallel()
		bad := legacyCall(t, `{"role":"system","content":"s"},{"role":"user","content":"x","function_call":"oops"},`+call+`,`+answer)
		assert.NotEqual(t, first.ID, bad.ID)
	})
}

func TestExecutedLegacyFunctionCallsNeedsAnAnswer(t *testing.T) {
	t.Parallel()
	ad, err := NewRegistry().GetAdapter(FormatOpenAI)
	require.NoError(t, err)
	for name, body := range map[string]string{
		"unanswered": `{"messages":[{"role":"assistant","function_call":{"name":"f","arguments":"{}"}}]}`,
		"other name": `{"messages":[{"role":"assistant","function_call":{"name":"f","arguments":"{}"}},{"role":"function","name":"g","content":"x"}]}`,
		"no list":    `{"messages":{"role":"user"}}`,
	} {
		assert.Empty(t, ExecutedLegacyFunctionCalls(ad, []byte(body)), name)
	}
	anthropic, err := NewRegistry().GetAdapter(FormatAnthropic)
	require.NoError(t, err)
	assert.Empty(t, ExecutedLegacyFunctionCalls(anthropic, []byte(`{"messages":[{"role":"assistant","function_call":{"name":"f"}},{"role":"function","name":"f"}]}`)))
}
