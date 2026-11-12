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

package a2a_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errStoreDown = errors.New("redis: connection refused")

type memStore struct {
	mu       sync.Mutex
	owners   map[a2a.OwnershipKey]a2a.Owner
	touched  map[a2a.OwnershipKey]int
	readErr  error
	writeErr error
}

func newMemStore() *memStore {
	return &memStore{owners: map[a2a.OwnershipKey]a2a.Owner{}, touched: map[a2a.OwnershipKey]int{}}
}

func (s *memStore) Owner(_ context.Context, key a2a.OwnershipKey) (*a2a.Owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return nil, s.readErr
	}
	o, ok := s.owners[key]
	if !ok {
		return nil, nil
	}
	return &o, nil
}

func (s *memStore) Claim(_ context.Context, key a2a.OwnershipKey, o a2a.Owner, ttl time.Duration) (bool, *a2a.Owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return false, nil, s.writeErr
	}
	if existing, ok := s.owners[key]; ok {
		return false, &existing, nil
	}
	s.owners[key] = o
	return true, nil, nil
}

func (s *memStore) Touch(_ context.Context, key a2a.OwnershipKey, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touched[key]++
	return s.writeErr
}

func (s *memStore) owner(h *harness, scope a2a.OwnershipScope, id string) (a2a.Owner, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.owners[h.key(scope, id)]
	return o, ok
}

func (s *memStore) set(h *harness, scope a2a.OwnershipScope, id string, o a2a.Owner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.owners[h.key(scope, id)] = o
}

func (h *harness) key(scope a2a.OwnershipScope, id string) a2a.OwnershipKey {
	return a2a.OwnershipKey{GatewayID: h.consumer.Consumer.GatewayID, RegistryID: h.agent.ID, Scope: scope, ID: id}
}

func (h *harness) as(user string) *harness {
	h.principal = &identity.Principal{Subject: consumerdomain.EndUserSubject(h.consumer.Consumer.ID, user), Method: identity.MethodAPIKey}
	return h
}

func (h *harness) owner() a2a.Owner {
	return a2a.Owner{ConsumerID: h.consumer.Consumer.ID, Subject: h.principal.Subject}
}

const (
	v03Task    = "6a0ff7b1-8fa8-4a3c-a46c-f12b1bfa1d34"
	v03Context = "ctx-1"
)

func v03TaskAnswer() []byte {
	return []byte(`{"jsonrpc":"2.0","id":7,"result":{"kind":"task","id":"` + v03Task + `","contextId":"` + v03Context + `","status":{"state":"working"}}}`)
}

func TestOwnershipIsRecordedFromTheFirstAnswer(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHarness(t, a2a.Version03, ag.URL, allow).as("u1")
	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"role":"user","parts":[{"kind":"text","text":"hi"}]}}`), nil)
	require.Nil(t, rpcErr)

	for _, scope := range []a2a.OwnershipScope{a2a.ScopeTask, a2a.ScopeContext} {
		id := map[a2a.OwnershipScope]string{a2a.ScopeTask: v03Task, a2a.ScopeContext: v03Context}[scope]
		o, ok := h.store.owner(h, scope, id)
		require.True(t, ok, scope)
		assert.Equal(t, h.owner(), o, scope)
	}

	_, rpcErr = h.send(t, rpcRequest("tasks/get", `{"id":"`+v03Task+`"}`), nil)
	require.Nil(t, rpcErr, "the owner reads its task")
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	assert.Equal(t, 1, h.store.touched[h.key(a2a.ScopeTask, v03Task)], "a call renews the binding")
}

func TestOnlyTheOwnerUsesATaskOrAContext(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body []byte
	}{
		{name: "read another caller's task", body: rpcRequest("tasks/get", `{"id":"`+v03Task+`"}`)},
		{name: "cancel another caller's task", body: rpcRequest("tasks/cancel", `{"id":"`+v03Task+`"}`)},
		{name: "continue another caller's context", body: rpcRequest("message/send", `{"message":{"contextId":"`+v03Context+`","parts":[]}}`)},
		{name: "continue another caller's task", body: rpcRequest("message/send", `{"message":{"taskId":"`+v03Task+`","parts":[]}}`)},
		{name: "unknown task", body: rpcRequest("tasks/get", `{"id":"expired"}`)},
		{name: "unknown context", body: rpcRequest("message/send", `{"message":{"contextId":"expired","parts":[]}}`)},
		{name: "reference another caller's task", body: rpcRequest("message/send", `{"message":{"referenceTaskIds":["`+v03Task+`"],"parts":[]}}`)},
		{name: "reference an unknown task", body: rpcRequest("message/send", `{"message":{"referenceTaskIds":["expired"],"parts":[]}}`)},
	}
	for _, tc := range cases {
		ag := newAgent(t, answer(v03TaskAnswer()))
		h := newHarness(t, a2a.Version03, ag.URL, allow).as("u1")
		h.store.set(h, a2a.ScopeTask, v03Task, h.owner())
		withSession := h.owner()
		withSession.UpstreamSession = "session-of-u1"
		h.store.set(h, a2a.ScopeContext, v03Context, withSession)
		h.as("u2")

		_, rpcErr := h.send(t, tc.body, nil)
		require.NotNil(t, rpcErr, tc.name)
		assert.Equal(t, a2a.TaskNotFound(a2a.Version03), rpcErr, tc.name)
		assert.Zero(t, ag.calls(), tc.name)
	}
}

func TestOwnershipFailsClosedWhenTheStoreCannotBeRead(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHarness(t, a2a.Version03, ag.URL, allow)
	h.store.readErr = errStoreDown
	_, rpcErr := h.send(t, rpcRequest("tasks/cancel", `{"id":"`+v03Task+`"}`), nil)
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.ReasonOwnershipUnavailable, reasonOf(t, rpcErr))
	assert.Zero(t, ag.calls())
}

func TestAnswerIsKeptWhenTheStoreCannotBeWritten(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHarness(t, a2a.Version03, ag.URL, allow)
	h.store.writeErr = errStoreDown
	result, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"parts":[]}}`), nil)
	require.Nil(t, rpcErr)
	assert.NotEmpty(t, result)
}

func TestAnswerNamingAnotherCallersTaskIsNotDelivered(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHarness(t, a2a.Version03, ag.URL, allow).as("u1")
	h.store.set(h, a2a.ScopeTask, v03Task, h.owner())
	h.as("u2")
	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"parts":[]}}`), nil)
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.ReasonOwnershipConflict, reasonOf(t, rpcErr))
}

// Two keys of one application without a user share its tasks; two users of
// one application do not.
func TestOwnerIsTheConsumerAndTheSubject(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHarness(t, a2a.Version03, ag.URL, allow)
	h.store.set(h, a2a.ScopeTask, v03Task, a2a.Owner{ConsumerID: h.consumer.Consumer.ID, Subject: consumerdomain.AppSubject(h.consumer.Consumer.ID)})
	h.principal = &identity.Principal{Subject: consumerdomain.AppSubject(h.consumer.Consumer.ID), Method: identity.MethodMTLS}
	_, rpcErr := h.send(t, rpcRequest("tasks/get", `{"id":"`+v03Task+`"}`), nil)
	require.Nil(t, rpcErr)

	h.store.set(h, a2a.ScopeTask, v03Task, a2a.Owner{ConsumerID: ids.New[ids.ConsumerKind](), Subject: h.principal.Subject})
	_, rpcErr = h.send(t, rpcRequest("tasks/get", `{"id":"`+v03Task+`"}`), nil)
	require.NotNil(t, rpcErr, "another consumer")
}

func TestAReferencedTaskIsOnlyChecked(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{"jsonrpc":"2.0","id":7,"result":{"kind":"message","messageId":"m-2","role":"agent","parts":[]}}`)))
	h := newHarness(t, a2a.Version03, ag.URL, allow).as("u1")
	referenced := h.owner()
	referenced.UpstreamSession = "session-of-the-referenced-task"
	h.store.set(h, a2a.ScopeTask, v03Task, referenced)

	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"referenceTaskIds":["`+v03Task+`"],"parts":[]}}`), nil)
	require.Nil(t, rpcErr)
	assert.Equal(t, 1, ag.calls())
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	assert.Zero(t, h.store.touched[h.key(a2a.ScopeTask, v03Task)], "a reference does not renew the binding")
}

func TestReferenceTaskIdsMustBeAShortList(t *testing.T) {
	t.Parallel()
	refIDs := make([]string, 33)
	for i := range refIDs {
		refIDs[i] = fmt.Sprintf("%q", fmt.Sprintf("t-%d", i))
	}
	for name, refs := range map[string]string{
		"not a list": `"` + v03Task + `"`,
		"too many":   "[" + strings.Join(refIDs, ",") + "]",
	} {
		ag := newAgent(t, answer(v03TaskAnswer()))
		h := newHarness(t, a2a.Version03, ag.URL, allow)
		_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"referenceTaskIds":`+refs+`,"parts":[]}}`), nil)
		require.NotNil(t, rpcErr, name)
		assert.Equal(t, a2a.CodeInvalidParams, rpcErr.Code, name)
		assert.Zero(t, ag.calls(), name)
	}
}

func TestCancelAnswersOnlyTheTaskState(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer([]byte(`{"jsonrpc":"2.0","id":7,"result":{"kind":"task","id":"`+v03Task+`","contextId":"`+v03Context+`","status":{"state":"canceled"},"artifacts":[{"parts":[{"kind":"text","text":"draft"}]}]}}`)))
	h := newHarness(t, a2a.Version03, ag.URL, allow).as("u1")
	h.store.set(h, a2a.ScopeTask, v03Task, h.owner())
	h.store.set(h, a2a.ScopeContext, v03Context, h.owner())

	result, rpcErr := h.send(t, rpcRequest("tasks/cancel", `{"id":"`+v03Task+`"}`), nil)
	require.Nil(t, rpcErr)
	assert.JSONEq(t, `{"kind":"task","id":"`+v03Task+`","contextId":"`+v03Context+`","status":{"state":"canceled"}}`, string(result))
}

func TestAConflictOnTheContextLeavesTheTaskUnclaimed(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHarness(t, a2a.Version03, ag.URL, allow).as("u1")
	h.store.set(h, a2a.ScopeContext, v03Context, h.owner())
	h.as("u2")

	_, rpcErr := h.send(t, rpcRequest("message/send", `{"message":{"parts":[]}}`), nil)
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.ReasonOwnershipConflict, reasonOf(t, rpcErr))
	_, claimed := h.store.owner(h, a2a.ScopeTask, v03Task)
	assert.False(t, claimed)
}
