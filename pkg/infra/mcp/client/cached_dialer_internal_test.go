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

package client

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCachedDialer_SessionIdleTTLBehavior(t *testing.T) {
	t.Parallel()

	var initializes atomic.Int64
	deleted := make(chan struct{}, 2)
	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				initializes.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	inner := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted <- struct{}{}
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)

	now := time.Date(2026, time.August, 10, 10, 0, 0, 0, time.UTC)
	dialer := NewCachedDialer(New(), slog.New(slog.DiscardHandler)).(*cachedDialer)
	dialer.now = func() time.Time { return now }
	target := appmcp.Target{URL: upstream.URL, PinKey: "gateway:registry"}

	first, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	now = now.Add(sessionIdleTTL)
	atBoundary, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("boundary connect: %v", err)
	}
	if initializes.Load() != 1 {
		t.Fatalf("initializes at TTL boundary = %d, want 1", initializes.Load())
	}
	now = now.Add(sessionIdleTTL + time.Nanosecond)
	afterExpiry, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("post-expiry connect: %v", err)
	}
	if initializes.Load() != 2 {
		t.Fatalf("initializes after TTL = %d, want 2", initializes.Load())
	}

	select {
	case <-deleted:
	case <-time.After(5 * time.Second):
		t.Fatal("expired session was not closed")
	}
	first.Close(context.Background())
	atBoundary.Close(context.Background())
	dialer.drop(context.Background(), afterExpiry.(*cachedUpstream).key, afterExpiry.(*cachedUpstream).sess())
}
