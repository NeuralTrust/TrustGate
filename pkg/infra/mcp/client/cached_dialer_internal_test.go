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
	"errors"
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

func TestCachedDialer_CanceledInitiatorDoesNotCancelSharedConnect(t *testing.T) {
	t.Parallel()

	var initializes atomic.Int64
	initializeStarted := make(chan struct{})
	releaseInitialize := make(chan struct{})
	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				if initializes.Add(1) == 1 {
					close(initializeStarted)
				}
				<-releaseInitialize
			}
			return next(ctx, method, req)
		}
	})
	upstream := httptest.NewServer(sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return server },
		nil,
	))
	t.Cleanup(upstream.Close)

	dialer := newCachedDialer(New(), slog.New(slog.DiscardHandler))
	joined := make(chan struct{}, 2)
	dialer.connectJoined = func() {
		joined <- struct{}{}
	}
	target := appmcp.Target{URL: upstream.URL, PinKey: "gateway:registry"}
	initiatorCtx, cancelInitiator := context.WithCancel(context.Background())
	initiatorResult := make(chan error, 1)
	go func() {
		_, err := dialer.Connect(initiatorCtx, target)
		initiatorResult <- err
	}()
	<-joined
	<-initializeStarted

	followerResult := make(chan error, 1)
	go func() {
		_, err := dialer.Connect(context.Background(), target)
		followerResult <- err
	}()
	<-joined
	cancelInitiator()
	if err := <-initiatorResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("initiator error = %v, want context canceled", err)
	}
	close(releaseInitialize)
	if err := <-followerResult; err != nil {
		t.Fatalf("follower connect: %v", err)
	}
	if got := initializes.Load(); got != 1 {
		t.Fatalf("initializes = %d, want 1", got)
	}
}

func TestCachedDialer_SharedConnectIsBounded(t *testing.T) {
	t.Parallel()

	initializeStarted := make(chan struct{})
	dialer := newCachedDialer(New(), slog.New(slog.DiscardHandler))
	dialer.timeout = 25 * time.Millisecond
	dialer.connect = func(ctx context.Context, _ appmcp.Target) (*Session, error) {
		close(initializeStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	result := make(chan error, 1)
	go func() {
		_, err := dialer.Connect(context.Background(), appmcp.Target{
			URL:    "https://mcp.example.com",
			PinKey: "gateway:registry",
		})
		result <- err
	}()
	<-initializeStarted
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("bounded connect returned nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bounded connect did not complete")
	}
}
