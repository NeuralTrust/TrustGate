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

package a2a

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ReasonStreamIdle is the -32092 reason of a stream the agent left silent.
const ReasonStreamIdle = "stream_idle"

const (
	maxEventBytes = 1 << 20
	cancelTimeout = 30 * time.Second
)

// The stream timers. A stream always ends before the load balancer's backend
// timeout, so the caller is told why and can resubscribe.
var (
	streamIdleTimeout = 120 * time.Second
	streamMaxDuration = 55 * time.Minute
)

// Stream is an agent's event stream for one call.
type Stream struct {
	x        *Exchange
	body     io.ReadCloser
	cancel   context.CancelFunc
	deadline time.Time
	task     string
	recorded [2]string
}

type sseEvent struct {
	data []byte
	err  error
}

// Open sends a streaming call and returns the agent's event stream. An agent
// that answers with a single JSON-RPC response has its error returned.
func (x *Exchange) Open(ctx context.Context) (*Stream, *RPCError) {
	s, rpcErr := x.open(ctx)
	if rpcErr != nil {
		x.finish(rpcErr)
	}
	return s, rpcErr
}

func (x *Exchange) open(ctx context.Context) (*Stream, *RPCError) {
	ctx, cancel := context.WithCancel(ctx)
	opening := time.AfterFunc(streamIdleTimeout, cancel)
	res, err := x.post(ctx, x.header, x.call.Body)
	if !opening.Stop() {
		if err == nil {
			_ = res.Body.Close()
		}
		err = context.DeadlineExceeded
	}
	if err != nil {
		cancel()
		return nil, upstreamFailure(err)
	}
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		defer cancel()
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
		if err != nil {
			return nil, upstreamFailure(err)
		}
		if _, rpcErr := x.provider.decode(x, res, body); rpcErr != nil {
			return nil, rpcErr
		}
		return nil, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	return &Stream{x: x, body: res.Body, cancel: cancel, deadline: time.Now().Add(streamMaxDuration), task: x.content.TaskID}, nil
}

// Deadline is when the stream ends at the latest.
func (s *Stream) Deadline() time.Time {
	return s.deadline
}

// Run relays the agent's events to emit as JSON-RPC responses with the
// caller's id. Each event with content passes the policies first. It returns
// when the agent ends the stream, emit fails because the caller left, or the
// gateway ends it: with an error event when an event is blocked (and the task
// is then cancelled on the agent), invalid or owned by another caller, or
// when the agent stays silent for too long or the stream reaches its maximum
// duration. Returning closes the upstream request.
func (s *Stream) Run(ctx context.Context, id json.RawMessage, emit func([]byte) error) {
	var ended *RPCError
	defer func() { s.x.finish(ended) }()
	defer s.cancel()
	defer func() { _ = s.body.Close() }()
	done := make(chan struct{})
	defer close(done)
	events := make(chan sseEvent)
	go s.read(events, done)

	idle := time.NewTimer(streamIdleTimeout)
	defer idle.Stop()
	end := time.NewTimer(time.Until(s.deadline))
	defer end.Stop()
	fail := func(rpcErr *RPCError) {
		ended = rpcErr
		_ = emit(Response(id, nil, rpcErr))
	}
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			if ev.err != nil {
				fail(readFailure(ev.err))
				return
			}
			idle.Reset(streamIdleTimeout)
			result, rpcErr := s.relay(ctx, ev.data)
			if rpcErr != nil {
				fail(rpcErr)
				return
			}
			if emit(Response(id, result, nil)) != nil {
				return
			}
		case <-idle.C:
			fail(GatewayFailure(ReasonStreamIdle))
			return
		case <-end.C:
			fail(GatewayFailure(ReasonStreamMaxDuration))
			return
		}
	}
}

// relay checks one event: its content against the policies and the task and
// context it names against their owners.
func (s *Stream) relay(ctx context.Context, data []byte) (json.RawMessage, *RPCError) {
	result, rpcErr := s.x.decode(data, http.StatusOK)
	if rpcErr != nil {
		return nil, rpcErr
	}
	content, rpcErr := s.x.resultContent(result)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if content.TaskID != "" {
		s.task = content.TaskID
	}
	if len(content.Parts) > 0 {
		if blocked := s.x.f.runner.PreResponse(ctx, s.x, content.Parts); blocked != nil {
			go s.x.cancelTask(s.task)
			return nil, blocked
		}
	}
	if named := [2]string{content.TaskID, content.ContextID}; named != s.recorded {
		if rpcErr := s.x.recordOwner(ctx, content); rpcErr != nil {
			return nil, rpcErr
		}
		s.recorded = named
	}
	return result, nil
}

// read sends the data of each server-sent event to events until the body
// ends or done is closed.
func (s *Stream) read(events chan<- sseEvent, done <-chan struct{}) {
	defer close(events)
	send := func(ev sseEvent) bool {
		select {
		case events <- ev:
			return true
		case <-done:
			return false
		}
	}
	scanner := bufio.NewScanner(s.body)
	scanner.Buffer(make([]byte, 0, 64<<10), maxEventBytes)
	var data []byte
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			if len(data) > 0 && !send(sseEvent{data: data}) {
				return
			}
			data = nil
			continue
		}
		if value, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			if data != nil {
				data = append(data, '\n')
			}
			data = append(data, bytes.TrimPrefix(value, []byte(" "))...)
		}
	}
	if err := scanner.Err(); err != nil {
		send(sseEvent{err: err})
		return
	}
	if len(data) > 0 {
		send(sseEvent{data: data})
	}
}

func readFailure(err error) *RPCError {
	if errors.Is(err, bufio.ErrTooLong) {
		return GatewayFailure(ReasonResponseTooLarge)
	}
	return GatewayFailure(ReasonUpstreamUnreachable)
}

// cancelTask asks the agent to cancel a task the gateway stopped relaying,
// without waiting on anyone.
func (x *Exchange) cancelTask(task string) {
	if task == "" {
		return
	}
	method := "tasks/cancel"
	if x.version == Version10 {
		method = "CancelTask"
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": uuid.NewString(), "method": method, "params": map[string]string{"id": task}})
	header := x.header.Clone()
	header.Set("Accept", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), cancelTimeout)
	defer cancel()
	res, err := x.do(ctx, header, body)
	if err != nil {
		x.f.logger.Warn("a2a task cancel failed", slog.String("registry_id", x.call.Agent.ID.String()), slog.String("error", err.Error()))
		return
	}
	_ = res.Body.Close()
}
