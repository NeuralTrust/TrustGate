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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sseAgent answers a stream call with the events of a fixture, one per
// flush, then holds the connection for hold (or until the client leaves).
// Any other call (a cancel) is answered with an empty result and recorded.
func sseAgent(t *testing.T, events [][]byte, hold time.Duration) (*agent, chan string) {
	t.Helper()
	cancels := make(chan string, 1)
	ag := newAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			cancels <- r.Header.Get("X-Agent-Key")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, ev := range events {
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(ev)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
		select {
		case <-time.After(hold):
		case <-r.Context().Done():
		}
	})
	return ag, cancels
}

func fixtureEvents(t *testing.T, name string) [][]byte {
	t.Helper()
	var events [][]byte
	for _, line := range bytes.Split(readFixture(t, name), []byte("\n")) {
		if data, ok := bytes.CutPrefix(line, []byte("data: ")); ok {
			events = append(events, data)
		}
	}
	return events
}

type collector struct {
	mu     sync.Mutex
	frames []json.RawMessage
	fail   int
}

func (c *collector) emit(frame []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail > 0 && len(c.frames) == c.fail {
		return errors.New("client went away")
	}
	c.frames = append(c.frames, append([]byte(nil), frame...))
	return nil
}

func (c *collector) responses(t *testing.T) []struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *a2a.RPCError   `json:"error"`
} {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *a2a.RPCError   `json:"error"`
	}, len(c.frames))
	for i, f := range c.frames {
		require.NoError(t, json.Unmarshal(f, &out[i]))
	}
	return out
}

func openStream(t *testing.T, h *harness, body []byte) *a2a.Stream {
	t.Helper()
	x, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, body, nil))
	require.Nil(t, rpcErr)
	require.True(t, x.Streams())
	s, rpcErr := x.Open(context.Background())
	require.Nil(t, rpcErr)
	return s
}

func streamRequest(v a2a.Version) []byte {
	if v == a2a.Version03 {
		return rpcRequest("message/stream", `{"message":{"role":"user","parts":[{"kind":"text","text":"book a flight"}]}}`)
	}
	return rpcRequest("SendStreamingMessage", `{"message":{"role":"ROLE_USER","parts":[{"text":"book a flight"}]}}`)
}

func TestStreamRelaysEveryEventWithTheCallersID(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		events := fixtureEvents(t, prefix+".stream.response.sse")
		ag, _ := sseAgent(t, events, 0)
		h := newHarness(t, v, ag.URL, allow)
		var got collector
		openStream(t, h, streamRequest(v)).Run(context.Background(), json.RawMessage(`7`), got.emit)

		responses := got.responses(t)
		require.Len(t, responses, len(events), prefix)
		for i, r := range responses {
			assert.JSONEq(t, `7`, string(r.ID), prefix)
			assert.JSONEq(t, string(resultOf(t, events[i])), string(r.Result), prefix)
		}
		_, ok := h.store.owner(h, a2a.ScopeContext, "ctx-1")
		assert.True(t, ok, "ownership is recorded from the events")
		req, _ := ag.request(0)
		assert.Equal(t, "text/event-stream", req.Header.Get("Accept"))
	}
}

// A policy blocking the third event: the caller gets the first two and the
// block, the stream closes and the agent is asked to cancel the task.
func TestStreamBlockedMidway(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		events := fixtureEvents(t, prefix+".stream.response.sse")
		ag, cancels := sseAgent(t, events, time.Minute)
		var mu sync.Mutex
		inspected := 0
		h := newHarness(t, v, ag.URL, func(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
			if in.Stage != policy.StagePreResponse || !bytes.Contains(in.Response.Body, []byte("itinerary")) {
				mu.Lock()
				inspected++
				mu.Unlock()
				return &appplugins.StageOutcome{}, nil
			}
			return nil, &appplugins.PluginError{StatusCode: http.StatusForbidden, Plugin: "trustguard"}
		})
		h.agent.A2ATarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "X-Agent-Key", Value: "k"}
		var got collector
		openStream(t, h, streamRequest(v)).Run(context.Background(), json.RawMessage(`7`), got.emit)

		responses := got.responses(t)
		require.Len(t, responses, 3, prefix)
		require.NotNil(t, responses[2].Error, prefix)
		assert.Equal(t, a2a.CodePolicyBlocked, responses[2].Error.Code, prefix)
		select {
		case key := <-cancels:
			assert.Equal(t, "k", key, "the cancel carries the registry credential")
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the agent was not asked to cancel the task", prefix)
		}
		_, body := ag.request(1)
		assert.Contains(t, string(body), map[a2a.Version]string{a2a.Version03: `"tasks/cancel"`, a2a.Version10: `"CancelTask"`}[v])
	}
}

func TestStreamMalformedEvent(t *testing.T) {
	t.Parallel()
	ag, _ := sseAgent(t, [][]byte{[]byte(`{"jsonrpc":"2.0","id":7,"result":{"kind":"other"}}`)}, time.Minute)
	h := newHarness(t, a2a.Version03, ag.URL, allow)
	var got collector
	openStream(t, h, streamRequest(a2a.Version03)).Run(context.Background(), json.RawMessage(`7`), got.emit)
	responses := got.responses(t)
	require.Len(t, responses, 1)
	assert.Equal(t, a2a.ReasonInvalidUpstreamResponse, reasonOf(t, responses[0].Error))
}

func TestStreamAnsweredWithJSON(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(readFixture(t, "v03.task_not_found.response.json")))
	h := newHarness(t, a2a.Version03, ag.URL, allow)
	x, rpcErr := h.forwarder.Prepare(context.Background(), h.call(t, streamRequest(a2a.Version03), nil))
	require.Nil(t, rpcErr)
	_, rpcErr = x.Open(context.Background())
	require.NotNil(t, rpcErr)
	assert.Equal(t, a2a.CodeTaskNotFound, rpcErr.Code)
}

func TestStreamTimers(t *testing.T) {
	cases := []struct {
		name        string
		idle, max   time.Duration
		events      int
		reason      string
		minDuration time.Duration
	}{
		{name: "idle", idle: 100 * time.Millisecond, max: time.Minute, reason: a2a.ReasonStreamIdle},
		{name: "max duration", idle: time.Minute, max: 200 * time.Millisecond, reason: a2a.ReasonStreamMaxDuration},
	}
	for _, tc := range cases {
		a2a.SetStreamTimers(t, tc.idle, tc.max)
		events := fixtureEvents(t, "v03.stream.response.sse")[:1]
		ag, _ := sseAgent(t, events, time.Minute)
		h := newHarness(t, a2a.Version03, ag.URL, allow)
		var got collector
		openStream(t, h, streamRequest(a2a.Version03)).Run(context.Background(), json.RawMessage(`7`), got.emit)
		responses := got.responses(t)
		require.Len(t, responses, 2, tc.name)
		assert.Equal(t, tc.reason, reasonOf(t, responses[1].Error), tc.name)
	}
}

// A caller that leaves ends the stream and the upstream call, and nothing the
// stream started outlives it.
func TestStreamCallerLeavesWithoutLeaks(t *testing.T) {
	before := runtime.NumGoroutine()
	events := fixtureEvents(t, "v03.stream.response.sse")
	ag, _ := sseAgent(t, events, time.Minute)
	h := newHarness(t, a2a.Version03, ag.URL, allow)
	got := collector{fail: 1}

	done := make(chan struct{})
	go func() {
		openStream(t, h, streamRequest(a2a.Version03)).Run(context.Background(), json.RawMessage(`7`), got.emit)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end when the caller left")
	}
	require.Len(t, got.responses(t), 1)

	ag.Close()
	http.DefaultClient.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "goroutines left behind")
}
