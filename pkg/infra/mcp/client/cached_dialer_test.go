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

package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type upstreamStub struct {
	srv     *httptest.Server
	handler atomic.Pointer[http.Handler]
	inits   atomic.Int64
}

func newUpstreamStub(t *testing.T) *upstreamStub {
	t.Helper()
	u := &upstreamStub{}
	u.reset()
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*u.handler.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstreamStub) reset() {
	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				u.inits.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	server.AddTool(
		&sdk.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok"}}}, nil
		},
	)
	var handler http.Handler = sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return server }, nil)
	u.handler.Store(&handler)
}

func newCachedDialer() appmcp.Dialer {
	return mcpclient.NewCachedDialer(mcpclient.New(), slog.New(slog.DiscardHandler))
}

func TestCachedDialer_ReusesSessionPerPinKey(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL, PinKey: "gw:consumer:reg"}

	for i := 0; i < 3; i++ {
		up, err := dialer.Connect(context.Background(), target)
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		if _, err := up.ListTools(context.Background()); err != nil {
			t.Fatalf("list %d: %v", i, err)
		}
		up.Close(context.Background())
	}
	if got := upstream.inits.Load(); got != 1 {
		t.Fatalf("expected 1 initialize for a pinned target, got %d", got)
	}
}

func TestCachedDialer_RecoversFromLostUpstreamSession(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL, PinKey: "gw:consumer:reg"}

	up, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := up.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("call: %v", err)
	}

	upstream.reset()

	up2, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if _, err := up2.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err == nil {
		t.Fatal("call on a lost session must propagate the error instead of retrying")
	}

	up3, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("reconnect after eviction: %v", err)
	}
	if _, err := up3.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("call after re-dial: %v", err)
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("expected 2 initializes in total (initial + recovery), got %d", got)
	}
}

func TestCachedDialer_ListRetriesAfterLostSession(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL, PinKey: "gw:consumer:reg"}

	up, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := up.ListTools(context.Background()); err != nil {
		t.Fatalf("list: %v", err)
	}

	upstream.reset()

	up2, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if _, err := up2.ListTools(context.Background()); err != nil {
		t.Fatalf("read-only list should transparently re-initialize and retry: %v", err)
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("expected 2 initializes in total (initial + recovery), got %d", got)
	}
}

func TestCachedDialer_DoesNotReconnectWithRejectedCredential(t *testing.T) {
	t.Parallel()
	var reject atomic.Bool
	var inits atomic.Int64
	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				inits.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if reject.Load() && readRequestMethod(t, req) == "tools/list" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)

	dialer := newCachedDialer()
	up, err := dialer.Connect(context.Background(), appmcp.Target{
		URL: srv.URL, PinKey: "gw:consumer:reg:user",
		Headers: map[string]string{"Authorization": "Bearer rejected"},
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	reject.Store(true)
	_, err = up.ListTools(context.Background())
	if !errors.Is(err, appmcp.ErrUpstreamUnauthorized) {
		t.Fatalf("error = %v, want ErrUpstreamUnauthorized", err)
	}
	if got := inits.Load(); got != 1 {
		t.Fatalf("initializes = %d, want no reconnect with the rejected credential", got)
	}
}

func TestCachedDialer_NoPinKeyConnectsFresh(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL}

	for i := 0; i < 2; i++ {
		up, err := dialer.Connect(context.Background(), target)
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		if _, err := up.ListTools(context.Background()); err != nil {
			t.Fatalf("list %d: %v", i, err)
		}
		up.Close(context.Background())
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("expected a fresh session per connect without a pin key, got %d inits", got)
	}
}

func TestCachedDialer_ClosingARedundantSessionDoesNotStallTheCache(t *testing.T) {
	t.Parallel()

	var dialling atomic.Int64
	bothDialling := make(chan struct{})
	tearingDown := make(chan struct{}, 4)
	finishTeardown := make(chan struct{})

	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				if n := dialling.Add(1); n <= 2 {
					if n == 2 {
						close(bothDialling)
					}
					<-bothDialling
				}
			}
			return next(ctx, method, req)
		}
	})
	inner := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			tearingDown <- struct{}{}
			<-finishTeardown
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	defer close(finishTeardown)

	dialer := newCachedDialer()
	for i := 0; i < 2; i++ {
		go func() {
			_, _ = dialer.Connect(context.Background(),
				appmcp.Target{URL: srv.URL, PinKey: "gw:consumer:reg"})
		}()
	}
	select {
	case <-tearingDown:
	case <-time.After(10 * time.Second):
		t.Fatal("the session that lost the race was never torn down")
	}

	dialled := make(chan error, 1)
	go func() {
		_, err := dialer.Connect(context.Background(),
			appmcp.Target{URL: srv.URL, PinKey: "gw:consumer:other"})
		dialled <- err
	}()
	select {
	case err := <-dialled:
		if err != nil {
			t.Fatalf("connect to a second registry: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a session lookup waited on the teardown round trip of an unrelated session")
	}
}

func TestCachedDialer_CredentialChangeGetsNewSession(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()

	for _, token := range []string{"Bearer a", "Bearer b"} {
		up, err := dialer.Connect(context.Background(), appmcp.Target{
			URL:     upstream.srv.URL,
			PinKey:  "gw:consumer:reg:user",
			Headers: map[string]string{"Authorization": token},
		})
		if err != nil {
			t.Fatalf("connect with %q: %v", token, err)
		}
		if _, err := up.ListTools(context.Background()); err != nil {
			t.Fatalf("list with %q: %v", token, err)
		}
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("expected distinct sessions per credential fingerprint, got %d inits", got)
	}
}
