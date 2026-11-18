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

package providers_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trackingReadCloser records whether Close was called.
type trackingReadCloser struct {
	r      io.Reader
	closed atomic.Bool
}

func (t *trackingReadCloser) Read(p []byte) (int, error) { return t.r.Read(p) }

func (t *trackingReadCloser) Close() error {
	t.closed.Store(true)
	return nil
}

// errAfterReader yields data once and then returns err on the next read.
type errAfterReader struct {
	data []byte
	err  error
	done bool
}

func (e *errAfterReader) Read(p []byte) (int, error) {
	if !e.done {
		e.done = true
		n := copy(p, e.data)
		return n, nil
	}
	return 0, e.err
}

func collect(t *testing.T, seq func(func([]byte, error) bool)) ([]string, error) {
	t.Helper()
	var lines []string
	var gotErr error
	for line, err := range seq {
		if err != nil {
			gotErr = err
			break
		}
		lines = append(lines, string(line))
	}
	return lines, gotErr
}

func TestStreamSSE_YieldsLinesAndStopsOnDone(t *testing.T) {
	body := &trackingReadCloser{r: strings.NewReader(
		"data: {\"a\":1}\n\ndata: [DONE]\n\ndata: {\"after\":true}\n",
	)}

	lines, err := collect(t, providers.StreamSSE(context.Background(), body))
	require.NoError(t, err)
	assert.Equal(t, []string{`data: {"a":1}`, ``, `data: [DONE]`, ``}, lines,
		"iteration must stop right after the [DONE] event and its one separator")
	assert.True(t, body.closed.Load(), "body must be closed when the iterator ends")
}

// The read stops at [DONE], before the blank line that ends its event on the
// wire, so StreamSSE supplies it. It must come whether or not the upstream
// sent one of its own, and only once: a same-format client gets these lines
// verbatim, and "data: [DONE]\n" without it is an event a strict SSE parser
// never dispatches.
func TestStreamSSE_DoneEventEndsWithOneSeparator(t *testing.T) {
	withSeparator := &trackingReadCloser{r: strings.NewReader("data: {\"a\":1}\n\ndata: [DONE]\n\n")}
	lines, err := collect(t, providers.StreamSSE(context.Background(), withSeparator))
	require.NoError(t, err)
	assert.Equal(t, []string{`data: {"a":1}`, ``, `data: [DONE]`, ``}, lines)

	withoutSeparator := &trackingReadCloser{r: strings.NewReader("data: {\"a\":1}\n\ndata: [DONE]")}
	lines, err = collect(t, providers.StreamSSE(context.Background(), withoutSeparator))
	require.NoError(t, err)
	assert.Equal(t, []string{`data: {"a":1}`, ``, `data: [DONE]`, ``}, lines)
}

// A consumer that stops on the [DONE] line itself does not get the separator
// pushed at it.
func TestStreamSSE_ConsumerStoppingOnDoneGetsNothingMore(t *testing.T) {
	body := &trackingReadCloser{r: strings.NewReader("data: [DONE]\n\n")}

	var lines []string
	for line, err := range providers.StreamSSE(context.Background(), body) {
		require.NoError(t, err)
		lines = append(lines, string(line))
		break
	}
	assert.Equal(t, []string{`data: [DONE]`}, lines)
	assert.True(t, body.closed.Load())
}

// A reset is the upstream abandoning the response. It used to count as a
// normal end of the body, so a truncated answer reached the client as a
// finished one.
func TestStreamSSE_ConnectionResetMidStreamIsAnError(t *testing.T) {
	body := &trackingReadCloser{r: &errAfterReader{data: []byte("data: a\n\n"), err: syscall.ECONNRESET}}

	lines, err := collect(t, providers.StreamSSE(context.Background(), body))
	require.Error(t, err)
	assert.ErrorIs(t, err, syscall.ECONNRESET)
	assert.Equal(t, []string{"data: a", ""}, lines)
	assert.True(t, body.closed.Load())
}

// The error a reset arrives as through net/http is an *net.OpError whose text
// ends in "connection reset by peer"; the text used to be matched and dropped.
func TestStreamSSE_ResetByPeerMessageIsAnError(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	require.Contains(t, reset.Error(), "connection reset by peer")
	body := &trackingReadCloser{r: &errAfterReader{data: []byte("data: a\n"), err: reset}}

	lines, err := collect(t, providers.StreamSSE(context.Background(), body))
	require.Error(t, err)
	assert.ErrorIs(t, err, syscall.ECONNRESET)
	assert.Equal(t, []string{"data: a"}, lines)
}

// A closed connection is ours only when ctx has ended, and that case ends with
// the context's error. One that closes under a live ctx did not come from us.
func TestStreamSSE_ClosedConnectionUnderALiveContextIsAnError(t *testing.T) {
	body := &trackingReadCloser{r: &errAfterReader{data: []byte("data: a\n"), err: net.ErrClosed}}

	lines, err := collect(t, providers.StreamSSE(context.Background(), body))
	require.Error(t, err)
	assert.ErrorIs(t, err, net.ErrClosed)
	assert.Equal(t, []string{"data: a"}, lines)
}

// A body whose reader wraps io.EOF still ends cleanly.
func TestStreamSSE_WrappedEOFEndsCleanly(t *testing.T) {
	body := &trackingReadCloser{r: &errAfterReader{data: []byte("data: a\n\n"), err: fmt.Errorf("body: %w", io.EOF)}}

	lines, err := collect(t, providers.StreamSSE(context.Background(), body))
	require.NoError(t, err)
	assert.Equal(t, []string{"data: a", ""}, lines)
}

// Closing the body when ctx ends makes the blocked read fail with "use of
// closed network connection"; the stream still ends with the context's error,
// never with that one.
func TestStreamSSE_ContextCancelMidReadEndsWithTheContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &closeUnblocksReader{first: []byte("data: a\n\n"), closed: make(chan struct{})}

	var lines []string
	var gotErr error
	for line, err := range providers.StreamSSE(ctx, body) {
		if err != nil {
			gotErr = err
			break
		}
		lines = append(lines, string(line))
		if len(lines) == 2 {
			// Cancelled while the next read is blocked, not between reads.
			time.AfterFunc(20*time.Millisecond, cancel)
		}
	}
	require.ErrorIs(t, gotErr, context.Canceled)
	assert.NotContains(t, gotErr.Error(), "closed network connection")
	assert.Equal(t, []string{"data: a", ""}, lines)
}

// closeUnblocksReader returns first, then blocks until Close, after which the
// read fails as a read on a closed net.Conn does.
type closeUnblocksReader struct {
	first  []byte
	sent   bool
	closed chan struct{}
	once   atomic.Bool
}

func (r *closeUnblocksReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, r.first), nil
	}
	<-r.closed
	return 0, &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}
}

func (r *closeUnblocksReader) Close() error {
	if r.once.CompareAndSwap(false, true) {
		close(r.closed)
	}
	return nil
}

func TestStreamSSE_BenignEOFEndsCleanly(t *testing.T) {
	body := &trackingReadCloser{r: strings.NewReader("data: {\"a\":1}\n\n")}

	lines, err := collect(t, providers.StreamSSE(context.Background(), body))
	require.NoError(t, err)
	assert.Equal(t, []string{`data: {"a":1}`, ``}, lines)
	assert.True(t, body.closed.Load())
}

func TestStreamSSE_MidStreamErrorSurfaces(t *testing.T) {
	boom := errors.New("boom")
	body := &trackingReadCloser{r: &errAfterReader{data: []byte("data: a\ndata: b\n"), err: boom}}

	lines, err := collect(t, providers.StreamSSE(context.Background(), body))
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.Equal(t, []string{"data: a", "data: b"}, lines)
	assert.True(t, body.closed.Load(), "body must be closed even on error")
}

func TestStreamSSE_ContextCancelStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := &trackingReadCloser{r: strings.NewReader("data: a\ndata: b\n")}

	_, err := collect(t, providers.StreamSSE(ctx, body))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.True(t, body.closed.Load())
}

func TestStreamSSE_ClosesBodyOnConsumerBreak(t *testing.T) {
	body := &trackingReadCloser{r: strings.NewReader("data: a\ndata: b\ndata: c\n")}

	var first string
	for line, err := range providers.StreamSSE(context.Background(), body) {
		require.NoError(t, err)
		first = string(line)
		break // early break must still close the body via the iterator's defer
	}
	assert.Equal(t, "data: a", first)
	assert.True(t, body.closed.Load(), "body must be closed when the consumer breaks early")
}

func TestStreamResponse_ClosesBodyAndNoGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	for i := 0; i < 50; i++ {
		body := &trackingReadCloser{r: strings.NewReader("data: x\n\ndata: [DONE]\n")}
		for _, err := range providers.StreamResponse(context.Background(), body) {
			require.NoError(t, err)
		}
		assert.True(t, body.closed.Load(), "StreamResponse must close the body (and cancel its timeout)")
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	assert.LessOrEqual(t, after, baseline+2,
		"goroutines must not grow across StreamResponse runs (baseline=%d after=%d)", baseline, after)
}

func TestStreamSSE_ContextEndInterruptsABlockedRead(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func() (context.Context, context.CancelFunc)
		wantErr error
	}{
		{
			name: "deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 200*time.Millisecond)
			},
			wantErr: context.DeadlineExceeded,
		},
		{
			name: "cancel",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(200*time.Millisecond, cancel)
				return ctx, cancel
			},
			wantErr: context.Canceled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstreamGone := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: {\"a\":1}\n\n")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				close(upstreamGone)
			}))
			t.Cleanup(srv.Close)
			resp, err := http.Get(srv.URL) // #nosec G107 -- test server URL
			require.NoError(t, err)

			ctx, cancel := tt.ctx()
			defer cancel()
			start := time.Now()
			lines, err := collect(t, providers.StreamSSE(ctx, resp.Body))

			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, []string{`data: {"a":1}`, ``}, lines)
			assert.Less(t, time.Since(start), 5*time.Second)
			select {
			case <-upstreamGone:
			case <-time.After(5 * time.Second):
				t.Fatal("the upstream connection stayed open")
			}
		})
	}
}
