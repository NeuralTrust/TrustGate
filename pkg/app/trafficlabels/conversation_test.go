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
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryConversations struct {
	mu      sync.Mutex
	store   map[ConversationKey][]string
	loadErr error
	loads   int
	saves   int
}

func newMemoryConversations() *memoryConversations {
	return &memoryConversations{store: make(map[ConversationKey][]string)}
}

func (m *memoryConversations) Load(_ context.Context, key ConversationKey) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return append([]string(nil), m.store[key]...), nil
}

func (m *memoryConversations) Save(_ context.Context, key ConversationKey, msgs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	m.store[key] = append([]string(nil), msgs...)
	return nil
}

func (m *memoryConversations) get(key ConversationKey) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store[key]
}

func (m *memoryConversations) touched() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loads > 0 || m.saves > 0
}

var testConversation = ConversationKey{GatewayID: "gw-1", ConsumerID: "consumer-1", SessionID: "sess-1"}

func responsesCandidate(body string) Candidate {
	c := candidate(enabledConfig())
	c.SourceFormat = adapter.FormatOpenAIResponses
	c.SessionID = testConversation.SessionID
	c.Body = []byte(body)
	return c
}

func newBufferedIntake(t *testing.T, conversations ConversationBuffer, q Queue, rec Recorder) *intake {
	t.Helper()
	if q == nil {
		q = newFakeQueue()
	}
	if rec == nil {
		rec = permissiveRecorder(t)
	}
	return newIntake(quietLogger(), adapter.NewRegistry(), q, rec, IntakeConfig{}, WithConversationBuffer(conversations))
}

const (
	continuationBody = `{"model":"gpt-4o","previous_response_id":"resp_1","input":"and the second invoice?"}`
	conversationBody = `{"model":"gpt-4o","conversation":{"id":"conv_1"},"input":"and the second invoice?"}`
	firstTurnBody    = `{"model":"gpt-4o","input":[` +
		`{"role":"user","content":"I was charged twice"},` +
		`{"role":"assistant","content":"Which invoice?"},` +
		`{"role":"user","content":"INV-42"},` +
		`{"role":"user","content":"please refund it"}]}`
)

func TestConversation_ContinuationUsesTheBufferPlusTheNewTurn(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{"previous_response_id": continuationBody, "conversation": conversationBody} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conversations := newMemoryConversations()
			conversations.store[testConversation] = []string{"I was charged twice", "INV-42", "please refund it"}
			in := newBufferedIntake(t, conversations, nil, nil)

			req, ok := in.build(context.Background(), responsesCandidate(body))

			require.True(t, ok)
			assert.Equal(t, "please refund it\nand the second invoice?", req.Text, "the window (2) spans the buffer and the new turn")
			assert.Equal(t, trafficlabel.HashText(req.Text), req.TextHash, "the cache key follows the classified text")
			assert.Equal(t,
				[]string{"I was charged twice", "INV-42", "please refund it", "and the second invoice?"},
				conversations.get(testConversation))
		})
	}
}

func TestConversation_FirstTurnUsesTheBodyAndSeedsTheBuffer(t *testing.T) {
	t.Parallel()
	conversations := newMemoryConversations()
	conversations.store[testConversation] = []string{"stale message from an earlier chain"}
	in := newBufferedIntake(t, conversations, nil, nil)

	req, ok := in.build(context.Background(), responsesCandidate(firstTurnBody))

	require.True(t, ok)
	assert.Equal(t, "INV-42\nplease refund it", req.Text, "a request carrying its own history is labeled from its body")
	assert.Equal(t, []string{"I was charged twice", "INV-42", "please refund it"}, conversations.get(testConversation),
		"the body replaces the buffer, never adds to it")
}

func TestConversation_OtherFormatsIgnoreTheBuffer(t *testing.T) {
	t.Parallel()
	conversations := newMemoryConversations()
	conversations.store[testConversation] = []string{"buffered"}
	in := newBufferedIntake(t, conversations, nil, nil)
	c := candidate(enabledConfig())
	c.SessionID = testConversation.SessionID

	req, ok := in.build(context.Background(), c)

	require.True(t, ok)
	assert.Equal(t, "INV-42\nyes, do it", req.Text)
	assert.False(t, conversations.touched(), "stateless chat completions carry their own history")
}

func TestConversation_ResponsesWithoutASessionIgnoreTheBuffer(t *testing.T) {
	t.Parallel()
	conversations := newMemoryConversations()
	in := newBufferedIntake(t, conversations, nil, nil)
	c := responsesCandidate(continuationBody)
	c.SessionID = ""

	req, ok := in.build(context.Background(), c)

	require.True(t, ok)
	assert.Equal(t, "and the second invoice?", req.Text)
	assert.False(t, conversations.touched())
}

func TestConversation_ExpiredOrUnreadableBufferFallsBackToTheBody(t *testing.T) {
	t.Parallel()

	expired := newMemoryConversations()
	in := newBufferedIntake(t, expired, nil, nil)
	req, ok := in.build(context.Background(), responsesCandidate(continuationBody))
	require.True(t, ok)
	assert.Equal(t, "and the second invoice?", req.Text)
	assert.Equal(t, []string{"and the second invoice?"}, expired.get(testConversation), "the new turn starts a fresh buffer")

	failing := newMemoryConversations()
	failing.loadErr = errors.New("redis down")
	in = newBufferedIntake(t, failing, nil, nil)
	req, ok = in.build(context.Background(), responsesCandidate(continuationBody))
	require.True(t, ok)
	assert.Equal(t, "and the second invoice?", req.Text)
}

func TestConversation_WithoutABufferContinuationsUseTheBody(t *testing.T) {
	t.Parallel()
	in := newIntake(quietLogger(), adapter.NewRegistry(), newFakeQueue(), permissiveRecorder(t), IntakeConfig{})

	req, ok := in.build(context.Background(), responsesCandidate(continuationBody))
	require.True(t, ok)
	assert.Equal(t, "and the second invoice?", req.Text)

	bufferOnly := responsesCandidate(continuationBody)
	bufferOnly.BufferOnly = true
	assert.False(t, in.Submit(bufferOnly), "nothing to keep without a buffer")
}

func TestConversation_SampledOutTurnUpdatesTheBufferWithoutClassifying(t *testing.T) {
	t.Parallel()
	conversations := newMemoryConversations()
	conversations.store[testConversation] = []string{"I was charged twice"}
	q := newFakeQueue()
	in := newBufferedIntake(t, conversations, q, NewMockRecorder(t))
	in.Start()

	c := responsesCandidate(continuationBody)
	c.BufferOnly = true
	require.True(t, in.Submit(c))
	require.NoError(t, in.Shutdown(context.Background()))

	assert.Zero(t, q.count(), "a sampled-out turn is never classified")
	assert.Equal(t, []string{"I was charged twice", "and the second invoice?"}, conversations.get(testConversation))
}

func TestConversation_BufferIsCapped(t *testing.T) {
	t.Parallel()
	full := make([]string, trafficlabel.MaxMessageWindow)
	for i := range full {
		full[i] = fmt.Sprintf("message %d", i)
	}
	conversations := newMemoryConversations()
	conversations.store[testConversation] = full
	in := newBufferedIntake(t, conversations, nil, nil)

	_, ok := in.build(context.Background(), responsesCandidate(continuationBody))
	require.True(t, ok)
	saved := conversations.get(testConversation)
	require.Len(t, saved, trafficlabel.MaxMessageWindow)
	assert.Equal(t, "message 1", saved[0])
	assert.Equal(t, "and the second invoice?", saved[len(saved)-1])

	big := strings.Repeat("b", trafficlabel.MaxTextChars-10)
	conversations.store[testConversation] = []string{"old", big}
	_, ok = in.build(context.Background(), responsesCandidate(continuationBody))
	require.True(t, ok)
	assert.Equal(t, []string{"and the second invoice?"}, conversations.get(testConversation),
		"the buffer never holds more than MaxTextChars")
}

func TestIsResponsesContinuation(t *testing.T) {
	t.Parallel()
	assert.True(t, isResponsesContinuation([]byte(continuationBody)))
	assert.True(t, isResponsesContinuation([]byte(conversationBody)))
	assert.True(t, isResponsesContinuation([]byte(`{"conversation":"conv_1"}`)))
	assert.False(t, isResponsesContinuation([]byte(firstTurnBody)))
	assert.False(t, isResponsesContinuation([]byte(`{"previous_response_id":null,"conversation":""}`)))
	assert.False(t, isResponsesContinuation([]byte(`not-json`)))
}
