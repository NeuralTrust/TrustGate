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

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keepaliveTestChunk = `data: {"id":"c","model":"m","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":"}}]}}]}`

func adaptResponsesStream(raw iter.Seq2[[]byte, error], opts ...streamOption) iter.Seq2[[]byte, error] {
	return adaptStream(raw, adapter.NewRegistry(), adapter.FormatOpenAIResponses, adapter.FormatOpenAI, slog.Default(), nil, opts...)
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(what)
	}
}

func liveUpstreamReaders() int {
	var b bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Count(b.String(), "pumpWithKeepalive")
}

func requireNoUpstreamReader(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for liveUpstreamReaders() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d upstream reader goroutines still running", liveUpstreamReaders())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPumpWithKeepalive_StopCancelsTheUpstream(t *testing.T) {
	clock := newFakeStreamClock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstreamDone := make(chan struct{})
	upstream := func(yield func([]byte, error) bool) {
		defer close(upstreamDone)
		<-ctx.Done()
		yield(nil, ctx.Err())
	}

	stream := adaptResponsesStream(upstream, clock.option(), withStreamCancel(cancel))
	go clock.tick(11 * time.Second)
	for line := range stream {
		assert.Equal(t, ": keepalive", string(line))
		break
	}

	waitClosed(t, upstreamDone, "the upstream read was not cancelled when the stream stopped")
}

func TestPumpWithKeepalive_ConsumerPanicReleasesTheReader(t *testing.T) {
	upstreamDone := make(chan struct{})
	upstream := func(yield func([]byte, error) bool) {
		defer close(upstreamDone)
		for yield([]byte(keepaliveTestChunk), nil) {
		}
	}

	recovered := func() (r any) {
		defer func() { r = recover() }()
		for range adaptResponsesStream(upstream, newFakeStreamClock().option()) {
			panic("consumer failed")
		}
		return nil
	}()

	assert.Equal(t, "consumer failed", recovered)
	waitClosed(t, upstreamDone, "the upstream reader stayed parked after the consumer panicked")
}

func TestPumpWithKeepalive_ReaderPanicIsRaisedOnTheConsumer(t *testing.T) {
	upstream := func(yield func([]byte, error) bool) {
		if !yield([]byte(keepaliveTestChunk), nil) {
			return
		}
		panic("upstream reader failed")
	}

	recovered := func() (r any) {
		defer func() { r = recover() }()
		for range adaptResponsesStream(upstream, newFakeStreamClock().option()) {
		}
		return nil
	}()

	assert.Equal(t, "upstream reader failed", recovered)
	requireNoUpstreamReader(t)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestPumpWithKeepalive_LateReaderPanicIsLogged(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pumpReturned := make(chan struct{})
	upstream := func(yield func([]byte, error) bool) {
		if !yield([]byte(keepaliveTestChunk), nil) {
			return
		}
		<-pumpReturned
		panic("late upstream reader failure")
	}
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	stream := adaptStream(upstream, adapter.NewRegistry(), adapter.FormatOpenAIResponses, adapter.FormatOpenAI,
		logger, nil, withStreamContext(ctx), newFakeStreamClock().option())

	assert.NotPanics(t, func() {
		for _, err := range stream {
			if err == nil {
				cancel()
			}
		}
	})
	close(pumpReturned)

	requireNoUpstreamReader(t)
	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "late upstream reader failure")
	}, 5*time.Second, 10*time.Millisecond)
	assert.Contains(t, logs.String(), "stack=")
}

type silentUpstream struct {
	srv    *httptest.Server
	closed chan struct{}
}

func newSilentUpstream(t *testing.T) *silentUpstream {
	t.Helper()
	u := &silentUpstream{closed: make(chan struct{})}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "%s\n\n", keepaliveTestChunk)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(u.closed)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *silentUpstream) open(t *testing.T, ctx context.Context) io.ReadCloser {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.srv.URL, nil)
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req) // #nosec G704 -- test server URL
	require.NoError(t, err)
	return resp.Body
}

func TestAdaptStream_ResponsesClientGoneWhileUpstreamSilentClosesTheUpstream(t *testing.T) {
	u := newSilentUpstream(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := newFakeStreamClock()
	raw := providers.StreamResponse(ctx, u.open(t, ctx))

	ticked := false
	for line, err := range adaptResponsesStream(raw, withStreamContext(ctx), withStreamCancel(cancel), clock.option()) {
		require.NoError(t, err)
		if string(line) == ": keepalive" {
			break
		}
		if !ticked {
			ticked = true
			go clock.tick(11 * time.Second)
		}
	}

	waitClosed(t, u.closed, "the upstream connection stayed open after the client went away")
	requireNoUpstreamReader(t)
}

func TestAdaptStream_ResponsesStreamDeadlineEndsASilentUpstream(t *testing.T) {
	u := newSilentUpstream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	raw := providers.StreamSSE(ctx, u.open(t, context.Background()))

	var lines []string
	var streamErr error
	start := time.Now()
	for line, err := range adaptResponsesStream(raw, newFakeStreamClock().option()) {
		if err != nil {
			streamErr = err
			break
		}
		lines = append(lines, string(line))
	}

	require.True(t, errors.Is(streamErr, context.DeadlineExceeded), "err = %v", streamErr)
	assert.Less(t, time.Since(start), 5*time.Second)
	final := requireResponsesContract(t, responsesWireEvents(t, lines))
	assert.Equal(t, "failed", final.Status)
	waitClosed(t, u.closed, "the upstream connection stayed open after the stream deadline")
	requireNoUpstreamReader(t)
}
