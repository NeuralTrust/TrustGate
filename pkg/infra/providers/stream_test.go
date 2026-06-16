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
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
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
	assert.Equal(t, []string{`data: {"a":1}`, ``, `data: [DONE]`}, lines,
		"iteration must stop right after the [DONE] marker")
	assert.True(t, body.closed.Load(), "body must be closed when the iterator ends")
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
