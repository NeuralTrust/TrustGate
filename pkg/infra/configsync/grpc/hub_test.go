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

package grpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type recordingStore struct {
	mu           sync.Mutex
	connected    []string
	acked        []string
	disconnected []string
	err          error
}

func (s *recordingStore) MarkConnected(_ context.Context, scope, instanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = append(s.connected, scope+"/"+instanceID)
	return s.err
}

func (s *recordingStore) MarkAck(_ context.Context, scope, instanceID, appliedVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acked = append(s.acked, scope+"/"+instanceID+"="+appliedVersion)
	return s.err
}

func (s *recordingStore) MarkDisconnected(_ context.Context, scope, instanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disconnected = append(s.disconnected, scope+"/"+instanceID)
	return s.err
}

func (s *recordingStore) snapshot() ([]string, []string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.connected...), append([]string(nil), s.acked...), append([]string(nil), s.disconnected...)
}

func TestHub_BroadcastLatestOnlyDropsOldest(t *testing.T) {
	h := NewHub(discardLogger(), nil)
	conn := h.register("", "dp-1")
	defer h.unregister(conn)

	h.Broadcast("v1")
	h.Broadcast("v2")
	h.Broadcast("v3")

	select {
	case got := <-conn.notices:
		if got != "v3" {
			t.Fatalf("notice = %q, want latest v3", got)
		}
	default:
		t.Fatal("expected a pending notice")
	}
	select {
	case extra := <-conn.notices:
		t.Fatalf("expected drained channel, got %q", extra)
	default:
	}
}

func TestHub_BroadcastNeverBlocksSlowConsumer(t *testing.T) {
	h := NewHub(discardLogger(), nil)
	conn := h.register("", "dp-slow")
	defer h.unregister(conn)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			h.Broadcast("v")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Broadcast blocked on a slow consumer")
	}
}

func TestHub_ConcurrentRegisterBroadcastAck(t *testing.T) {
	h := NewHub(discardLogger(), nil)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				h.Broadcast("v")
			}
		}
	}()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				conn := h.register("", "dp")
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						case v := <-conn.notices:
							conn.recordAck(v)
						}
					}
				}()
				_ = conn.acked()
				h.unregister(conn)
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestHub_RegisterCarriesScopeAndMarksConnected(t *testing.T) {
	store := &recordingStore{}
	h := NewHub(discardLogger(), store)

	conn := h.register("tenant-a", "dp-1")
	defer h.unregister(conn)

	if conn.scope != "tenant-a" {
		t.Fatalf("connection.scope = %q, want tenant-a", conn.scope)
	}
	connected, _, _ := store.snapshot()
	if len(connected) != 1 || connected[0] != "tenant-a/dp-1" {
		t.Fatalf("MarkConnected = %v, want [tenant-a/dp-1]", connected)
	}
}

func TestHub_MarkAckPersistsAppliedVersion(t *testing.T) {
	store := &recordingStore{}
	h := NewHub(discardLogger(), store)

	conn := h.register("tenant-a", "dp-1")
	defer h.unregister(conn)

	h.markAck(conn, "v42")

	if got := conn.acked(); got != "v42" {
		t.Fatalf("conn.acked() = %q, want v42", got)
	}
	_, acked, _ := store.snapshot()
	if len(acked) != 1 || acked[0] != "tenant-a/dp-1=v42" {
		t.Fatalf("MarkAck = %v, want [tenant-a/dp-1=v42]", acked)
	}
}

func TestHub_MarkDisconnected(t *testing.T) {
	store := &recordingStore{}
	h := NewHub(discardLogger(), store)

	conn := h.register("tenant-a", "dp-1")
	h.markDisconnected(conn)
	h.unregister(conn)

	_, _, disconnected := store.snapshot()
	if len(disconnected) != 1 || disconnected[0] != "tenant-a/dp-1" {
		t.Fatalf("MarkDisconnected = %v, want [tenant-a/dp-1]", disconnected)
	}
}

func TestHub_StoreErrorsAreSwallowed(t *testing.T) {
	store := &recordingStore{err: errors.New("db down")}
	h := NewHub(discardLogger(), store)

	conn := h.register("tenant-a", "dp-1")
	h.markAck(conn, "v1")
	h.markDisconnected(conn)
	h.unregister(conn)

	connected, acked, disconnected := store.snapshot()
	if len(connected) != 1 || len(acked) != 1 || len(disconnected) != 1 {
		t.Fatalf("store writes were attempted but errors must not abort: connected=%v acked=%v disconnected=%v", connected, acked, disconnected)
	}
}

func TestHub_NilStoreIsNoOp(t *testing.T) {
	h := NewHub(discardLogger(), nil)

	conn := h.register("tenant-a", "dp-1")
	h.markAck(conn, "v1")
	h.markDisconnected(conn)
	h.unregister(conn)

	if got := conn.acked(); got != "v1" {
		t.Fatalf("conn.acked() = %q, want v1 (ack recording must work without a store)", got)
	}
}
