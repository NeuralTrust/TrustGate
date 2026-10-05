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

package trafficlabels

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const openAIConversation = `{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "You are the billing assistant of ACME."},
    {"role": "user", "content": "I was charged twice"},
    {"role": "assistant", "content": "Sorry to hear that. Which invoice?"},
    {"role": "user", "content": "INV-42"},
    {"role": "assistant", "content": "I can refund it."},
    {"role": "user", "content": "yes, do it"}
  ]
}`

const anthropicConversation = `{
  "model": "claude-sonnet-5",
  "max_tokens": 256,
  "system": "You are the legal assistant.",
  "messages": [
    {"role": "user", "content": "Can I terminate the contract early?"},
    {"role": "assistant", "content": "It depends on clause 9."},
    {"role": "user", "content": [{"type": "text", "text": "Clause 9 says 30 days notice."}]}
  ]
}`

func TestUserText(t *testing.T) {
	t.Parallel()
	registry := adapter.NewRegistry()

	tests := []struct {
		name   string
		body   string
		format adapter.Format
		window int
		want   string
	}{
		{
			name:   "keeps the last user turns in order and skips system and assistant",
			body:   openAIConversation,
			format: adapter.FormatOpenAI,
			window: 2,
			want:   "INV-42\nyes, do it",
		},
		{
			name:   "window larger than the conversation takes every user turn",
			body:   openAIConversation,
			format: adapter.FormatOpenAI,
			window: 10,
			want:   "I was charged twice\nINV-42\nyes, do it",
		},
		{
			name:   "detects the format when the route did not set it",
			body:   openAIConversation,
			window: 1,
			want:   "yes, do it",
		},
		{
			name:   "anthropic content blocks",
			body:   anthropicConversation,
			format: adapter.FormatAnthropic,
			window: 3,
			want:   "Can I terminate the contract early?\nClause 9 says 30 days notice.",
		},
		{
			name:   "malformed body yields nothing",
			body:   `{"messages": [`,
			format: adapter.FormatOpenAI,
			window: 3,
			want:   "",
		},
		{
			name:   "no user message yields nothing",
			body:   `{"model":"gpt-4o","messages":[{"role":"system","content":"only a system prompt"}]}`,
			format: adapter.FormatOpenAI,
			window: 3,
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, userText(registry, []byte(tt.body), tt.format, tt.window))
		})
	}
}

func TestUserTextWithoutBodyOrDecoder(t *testing.T) {
	t.Parallel()
	assert.Empty(t, userText(adapter.NewRegistry(), nil, adapter.FormatOpenAI, 3))
	assert.Empty(t, userText(nil, []byte(openAIConversation), adapter.FormatOpenAI, 3))
}

func TestUserMessagesSkipBlankTurns(t *testing.T) {
	t.Parallel()
	body := []byte(`{"model":"gpt-4o","messages":[` +
		`{"role":"user","content":"first"},{"role":"user","content":"   "},{"role":"user","content":"second"}]}`)
	msgs := userMessages(adapter.NewRegistry(), body, adapter.FormatOpenAI)
	assert.Equal(t, []string{"first", "second"}, msgs)
	assert.Equal(t, "first\nsecond", lastUserMessages(msgs, 2))
	assert.Empty(t, lastUserMessages(msgs, 0))
}

func TestCapConversationKeepsTheMostRecentMessages(t *testing.T) {
	t.Parallel()

	many := make([]string, trafficlabel.MaxMessageWindow+10)
	for i := range many {
		many[i] = strings.Repeat("m", 3) + string(rune('a'+i%26))
	}
	capped := capConversation(many)
	require.Len(t, capped, trafficlabel.MaxMessageWindow)
	assert.Equal(t, many[10:], capped)

	half := strings.Repeat("h", trafficlabel.MaxTextChars/2)
	byChars := capConversation([]string{"oldest", half, half})
	assert.Equal(t, []string{half, half}, byChars, "the oldest messages go first once the text budget is spent")

	huge := strings.Repeat("x", trafficlabel.MaxTextChars) + "tail"
	single := capConversation([]string{"older", huge})
	require.Len(t, single, 1)
	assert.Equal(t, trafficlabel.MaxTextChars, utf8.RuneCountInString(single[0]))
	assert.True(t, strings.HasSuffix(single[0], "tail"))

	assert.Empty(t, capConversation(nil))
}

func TestTruncateTailKeepsTheLatestText(t *testing.T) {
	t.Parallel()

	short := "ok"
	assert.Equal(t, short, truncateTail(short, trafficlabel.MaxTextChars))

	long := strings.Repeat("é", 20) + "the latest turn"
	got := truncateTail(long, 18)
	require.True(t, utf8.ValidString(got))
	assert.Equal(t, 18, utf8.RuneCountInString(got))
	assert.True(t, strings.HasSuffix(got, "the latest turn"))
}
