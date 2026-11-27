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
	"unicode/utf8"

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
	x    *Exchange
	body io.ReadCloser
	// translate reads a provider's own stream, for an agent the gateway
	// translates; nil reads server-sent JSON-RPC events.
	translate streamTranslator
	cancel    context.CancelFunc
	deadline  time.Time
	task      string
	recorded  [2]string
	// released holds, by artifact, the end of the text already relayed for
	// it (priorBytes at most), read before the next chunk that appends to it.
	released map[string]string
}

// priorBytes is how much of an artifact's relayed text is read before each
// chunk that appends to it. Policies read every chunk on its own, so a value
// split across two chunks would be seen whole in neither; reading it after
// the end of the previous chunk shows whole any value that straddles the
// boundary within this many bytes (an email, a card or account number, a
// phrase). It is resent with every chunk, so it is kept small.
const priorBytes = 1024

// withPrior sets, on the first text part of an artifact chunk that appends to
// what was relayed, the end of that text (Part.Prior).
func (s *Stream) withPrior(c *Content) {
	if c.ArtifactID == "" || !c.Append {
		return
	}
	prior := s.released[c.ArtifactID]
	if prior == "" {
		return
	}
	for i, p := range c.Parts {
		if p.Type == PartText && inPartList(c.Paths[i]) {
			c.Parts[i].Prior = prior
			return
		}
	}
}

// remember keeps the end of the text an artifact chunk relayed, for the next
// chunk that appends to it, and forgets the artifact on its last chunk.
func (s *Stream) remember(c Content) {
	if c.ArtifactID == "" {
		return
	}
	if c.LastChunk {
		delete(s.released, c.ArtifactID)
		return
	}
	var text strings.Builder
	if c.Append {
		text.WriteString(s.released[c.ArtifactID])
	}
	for i, p := range c.Parts {
		if p.Type == PartText && i < len(c.Paths) && inPartList(c.Paths[i]) {
			text.WriteString(p.Text)
		}
	}
	if s.released == nil {
		s.released = make(map[string]string)
	}
	s.released[c.ArtifactID] = tail(text.String(), priorBytes)
}

// inPartList reports whether path is a part's value in a list of parts
// (…, "parts", i, "text"), not a name or a description.
func inPartList(path Path) bool {
	n := len(path)
	if n < 3 {
		return false
	}
	_, isIndex := path[n-2].(int)
	return isIndex && path[n-3] == "parts"
}

// tail is the last n bytes of s at most, starting on a rune.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
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
	translate, translates := x.provider.(streamTranslator)
	if translates && res.StatusCode >= 200 && res.StatusCode <= 299 {
		return &Stream{x: x, body: res.Body, translate: translate, cancel: cancel, deadline: time.Now().Add(streamMaxDuration), task: x.content.TaskID}, nil
	}
	if translates || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		defer cancel()
		defer func() { _ = res.Body.Close() }()
		reading := time.AfterFunc(upstreamTimeout, cancel)
		body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
		if !reading.Stop() {
			return nil, GatewayFailure(ReasonUpstreamTimeout)
		}
		if err != nil {
			return nil, upstreamFailure(err)
		}
		if _, rpcErr, fromAgent := x.provider.decode(x, res, body); rpcErr != nil {
			x.agentError = fromAgent
			return nil, rpcErr
		}
		return nil, GatewayFailure(ReasonInvalidUpstreamResponse)
	}
	return &Stream{x: x, body: res.Body, cancel: cancel, deadline: time.Now().Add(streamMaxDuration), task: x.content.TaskID}, nil
}

// Discard closes a stream that Run will never relay and frees what plugins
// hold for the call.
func (s *Stream) Discard() {
	_ = s.body.Close()
	s.cancel()
	s.x.done.Run()
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
		// The caller may have left; the stream ends either way.
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
	result, rpcErr, fromAgent := decodeRPC(data, http.StatusOK)
	if rpcErr != nil {
		s.x.agentError = fromAgent
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
		s.withPrior(&content)
		masked, blocked := s.x.f.runner.PreResponse(ctx, s.x, content, result)
		if blocked != nil {
			go s.x.cancelTask(ctx, s.task)
			return nil, blocked
		}
		if !bytes.Equal(masked, result) {
			// What is relayed is the masked event, and it is what later
			// chunks are read after.
			result = masked
			if relayed, rpcErr := ResultContent(s.x.version, result); rpcErr == nil {
				content.Parts = relayed.Parts
			}
		}
		s.remember(content)
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
	if s.translate != nil {
		s.translate.readStream(s.x, s.body, send)
		return
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
			value = bytes.TrimPrefix(value, []byte(" "))
			if len(data)+1+len(value) > maxEventBytes {
				send(sseEvent{err: bufio.ErrTooLong})
				return
			}
			if data != nil {
				data = append(data, '\n')
			}
			data = append(data, value...)
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
func (x *Exchange) cancelTask(ctx context.Context, task string) {
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
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cancelTimeout)
	defer cancel()
	res, err := x.do(ctx, header, body)
	if err != nil {
		x.f.logger.Warn("a2a task cancel failed", slog.String("registry_id", x.call.Agent.ID.String()), slog.String("error", err.Error()))
		return
	}
	_ = res.Body.Close()
}
