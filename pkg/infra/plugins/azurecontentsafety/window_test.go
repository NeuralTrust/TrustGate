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

package azurecontentsafety

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func wireData(t *testing.T, d *Data) map[string]any {
	t.Helper()
	raw, err := json.Marshal(d)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// agentConversation is what an agent or RAG call looks like: a system prompt,
// the user's question, an assistant tool call and a large tool result.
func agentConversation(t *testing.T, question string) []byte {
	t.Helper()
	return chatBody(t,
		map[string]string{"role": "system", "content": strings.Repeat("s", 4000)},
		map[string]string{"role": "user", "content": question},
		map[string]string{"role": "assistant", "content": "calling the search tool"},
		map[string]string{"role": "tool", "content": strings.Repeat("r", 9000)},
	)
}

// A long agent conversation is analysed over a window instead of being refused:
// the window holds the whole last user message, never more than text:analyze
// accepts, and the verdict is Azure's.
func TestALongAgentConversationIsAnalysedOverAWindow(t *testing.T) {
	t.Parallel()
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}),
		requestContext(agentConversation(t, "what does the report say?")))
	in.Event = event

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)

	sent := f.sent()
	require.Len(t, sent, 1)
	assert.LessOrEqual(t, len([]rune(sent[0])), azureTextLimit)
	assert.Contains(t, sent[0], "what does the report say?")
	assert.True(t, strings.HasSuffix(sent[0], strings.Repeat("r", 100)), "the window ends on the most recent content")

	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "allowed", extras.Decision)
}

// A payload in the last user message is judged even when the tool results after
// it alone would fill the window.
func TestTheWindowAlwaysHoldsTheWholeLastUserMessage(t *testing.T) {
	t.Parallel()
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	question := "FLAGGED " + strings.Repeat("q", 3000)
	body := chatBody(t,
		map[string]string{"role": "user", "content": question},
		map[string]string{"role": "tool", "content": strings.Repeat("r", 12000)},
	)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(body))

	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.NotEqual(t, appplugins.TypeGuardrailInputUninspectable, pe.Type, "Azure's verdict, not a local refusal")
	sent := f.sent()
	require.Len(t, sent, 1)
	assert.Contains(t, sent[0], question)
	assert.LessOrEqual(t, len([]rune(sent[0])), azureTextLimit)
}

// What the window left out is on the event, so a partial inspection never reads
// as a whole one.
func TestTheLeftOutPartOfAWindowIsRecorded(t *testing.T) {
	t.Parallel()
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}),
		requestContext(agentConversation(t, "what does the report say?")))
	in.Event = event
	_, err := p.Execute(context.Background(), in)
	require.NoError(t, err)

	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	wire := wireData(t, extras)
	assert.Equal(t, true, wire["partial_window"])
	total := 4000 + 1 + len("what does the report say?") + 1 + len("calling the search tool") + 1 + 9000
	assert.EqualValues(t, total-len([]rune(f.sent()[0])), wire["chars_not_inspected"])
}

func TestAConversationThatFitsIsNotMarkedPartial(t *testing.T) {
	t.Parallel()
	f := &limitedAzure{}
	srv := f.server(t)
	p := New(adapter.NewRegistry(), nil)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}),
		requestContext(chatBody(t, map[string]string{"role": "user", "content": "hello"})))
	in.Event = event
	_, err := p.Execute(context.Background(), in)
	require.NoError(t, err)

	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.NotContains(t, wireData(t, extras), "partial_window")
}

// A last user message that alone does not fit is the client's input: it cannot
// be windowed without leaving part of what the user wrote unjudged.
func TestALastUserMessageOverTheLimitIsInput(t *testing.T) {
	t.Parallel()
	body := chatBody(t,
		map[string]string{"role": "system", "content": "be safe"},
		map[string]string{"role": "user", "content": strings.Repeat("u", azureTextLimit+1)},
		map[string]string{"role": "tool", "content": "result"},
	)
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			f := &limitedAzure{}
			srv := f.server(t)
			p := New(adapter.NewRegistry(), nil)
			event, span := eventFor(t)
			in := execInput(policy.StagePreRequest, mode, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(body))
			in.Event = event

			res, err := p.Execute(context.Background(), in)
			extras, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, "input", extras.FailureClass)
			assert.Equal(t, appplugins.DetailPayloadTooLarge, extras.FailureDetail)
			assert.Empty(t, f.sent())
			if mode == policy.ModeEnforce {
				pe, isPE := appplugins.AsPluginError(err)
				require.True(t, isPE, "got %v", err)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
		})
	}
}
