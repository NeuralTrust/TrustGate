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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type closedConnection struct{}

func (closedConnection) Write([]byte) (int, error) {
	return 0, errors.New("connection reset by peer")
}

func TestStreamToolChanges_PushesOnceWhenConnectedAccountsChange(t *testing.T) {
	t.Parallel()
	out := &syncBuffer{}
	writer := bufio.NewWriter(out)
	var mu sync.Mutex
	connected := "cx:linear@2026-08-28T09:00:00Z"
	snapshot := func() string {
		mu.Lock()
		defer mu.Unlock()
		return connected
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		connected = "cx:linear@2026-08-28T09:00:00Z|cx:notion@2026-08-28T09:05:00Z"
		mu.Unlock()
	}()

	streamToolChanges(writer, snapshot, streamTimings{
		poll:      2 * time.Millisecond,
		keepAlive: time.Hour,
		lifetime:  200 * time.Millisecond,
	})

	body := out.String()
	require.Equal(t, 1, strings.Count(body, "notifications/tools/list_changed"),
		"a single connection change must push exactly one notification")
	require.Contains(t, body, "event: message")
}

func TestStreamToolChanges_StaysQuietWhileNothingChanges(t *testing.T) {
	t.Parallel()
	out := &syncBuffer{}
	writer := bufio.NewWriter(out)

	streamToolChanges(writer, func() string { return "cx:linear@2026-08-28T09:00:00Z" }, streamTimings{
		poll:      2 * time.Millisecond,
		keepAlive: 5 * time.Millisecond,
		lifetime:  60 * time.Millisecond,
	})

	body := out.String()
	require.NotContains(t, body, "notifications/tools/list_changed")
	require.Contains(t, body, ": keepalive")
}

func TestStreamToolChanges_StopsWhenTheClientIsGone(t *testing.T) {
	t.Parallel()
	writer := bufio.NewWriterSize(closedConnection{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		streamToolChanges(writer, func() string { return "" }, streamTimings{
			poll:      time.Millisecond,
			keepAlive: time.Millisecond,
			lifetime:  10 * time.Second,
		})
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream kept running after the connection failed; an unreachable client must not hold a goroutine open")
	}
}
