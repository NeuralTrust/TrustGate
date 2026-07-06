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
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHub_BroadcastLatestOnlyDropsOldest(t *testing.T) {
	h := NewHub(discardLogger())
	conn := h.register("dp-1")
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
	h := NewHub(discardLogger())
	conn := h.register("dp-slow")
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
	h := NewHub(discardLogger())
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
				conn := h.register("dp")
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
