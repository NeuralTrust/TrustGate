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

package mcp

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestSink(maxBytes int) (*bufioSink, *bytes.Buffer) {
	var out bytes.Buffer
	return newBufioSink(bufio.NewWriter(&out), maxBytes), &out
}

func TestBufioSinkWritesExactWireBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		write func(*bufioSink) error
		want  string
	}{
		{
			name:  "message frame is one event and one data line",
			write: func(s *bufioSink) error { return s.Frame([]byte(`{"jsonrpc":"2.0"}`)) },
			want:  "event: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n",
		},
		{
			name:  "keepalive is a comment",
			write: func(s *bufioSink) error { return s.Comment(sseKeepalive) },
			want:  ": keepalive\n\n",
		},
		{
			name:  "an empty payload still terminates the frame",
			write: func(s *bufioSink) error { return s.Frame(nil) },
			want:  "event: message\ndata: \n\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink, out := newTestSink(defaultSubscriptionMaxEventBytes)
			require.NoError(t, tc.write(sink))
			require.NoError(t, sink.Flush())
			require.Equal(t, tc.want, out.String())
		})
	}
}

// An SSE id is a resumption cursor the client may replay through Last-Event-ID.
// A stateless gateway keeps no frame history, so the field must never appear.
func TestBufioSinkNeverWritesAnEventID(t *testing.T) {
	t.Parallel()
	sink, out := newTestSink(defaultSubscriptionMaxEventBytes)
	require.NoError(t, sink.Frame([]byte(`{"id":7,"method":"notifications/tools/list_changed"}`)))
	require.NoError(t, sink.Comment(sseKeepalive))
	require.NoError(t, sink.Flush())

	for _, line := range strings.Split(out.String(), "\n") {
		require.False(t, strings.HasPrefix(line, "id:"), "frame carries an SSE id field: %q", line)
		require.False(t, strings.HasPrefix(line, "retry:"), "frame carries an SSE retry field: %q", line)
	}
}

// A payload is written as a single data line, so a client scanner never has to
// reassemble a multi-line JSON-RPC envelope.
func TestBufioSinkWritesOneDataLinePerFrame(t *testing.T) {
	t.Parallel()
	sink, out := newTestSink(defaultSubscriptionMaxEventBytes)
	require.NoError(t, sink.Frame([]byte(`{"params":{"text":"a\nb"}}`)))
	require.NoError(t, sink.Flush())

	require.Equal(t, 1, strings.Count(out.String(), "data: "))
	require.Equal(t, "event: message\ndata: {\"params\":{\"text\":\"a\\nb\"}}\n\n", out.String())
}

func TestBufioSinkRejectsRatherThanTruncates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		maxBytes int
		write    func(*bufioSink) error
	}{
		{
			name:     "frame over the bound",
			maxBytes: 32,
			write:    func(s *bufioSink) error { return s.Frame([]byte(strings.Repeat("x", 64))) },
		},
		{
			name:     "comment over the bound",
			maxBytes: 4,
			write:    func(s *bufioSink) error { return s.Comment(sseKeepalive) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sink, out := newTestSink(tc.maxBytes)
			err := tc.write(sink)
			require.ErrorIs(t, err, ErrFrameTooLarge)
			require.NoError(t, sink.Flush())
			require.Empty(t, out.String(), "an oversize frame must not be partially written")
		})
	}
}

func TestBufioSinkAcceptsExactlyTheBound(t *testing.T) {
	t.Parallel()
	payload := []byte(strings.Repeat("x", 8))
	size := len(sseEventField) + len(sseDataField) + len(payload) + 2

	sink, out := newTestSink(size)
	require.NoError(t, sink.Frame(payload))
	require.NoError(t, sink.Flush())
	require.Len(t, out.String(), size)

	tight, _ := newTestSink(size - 1)
	require.ErrorIs(t, tight.Frame(payload), ErrFrameTooLarge)
}

func TestBufioSinkPropagatesWriteFailures(t *testing.T) {
	t.Parallel()
	sink := newBufioSink(bufio.NewWriterSize(failingWriter{}, 1), defaultSubscriptionMaxEventBytes)

	err := sink.Frame([]byte(`{"jsonrpc":"2.0"}`))
	if err == nil {
		err = sink.Flush()
	}
	require.ErrorIs(t, err, errWriteFailed)
}

var errWriteFailed = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }
