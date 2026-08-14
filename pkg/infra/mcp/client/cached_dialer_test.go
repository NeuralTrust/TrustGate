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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type upstreamStub struct {
	srv       *httptest.Server
	handler   atomic.Pointer[http.Handler]
	inits     atomic.Int64
	discovers atomic.Int64
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
			if method == "server/discover" {
				u.discovers.Add(1)
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
	if got := upstream.discovers.Load(); got != 0 {
		t.Fatalf("server/discover reached legacy upstream %d times", got)
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
	if got := upstream.discovers.Load(); got != 0 {
		t.Fatalf("server/discover reached legacy upstream %d times", got)
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
	if got := upstream.discovers.Load(); got != 0 {
		t.Fatalf("server/discover reached legacy upstream %d times", got)
	}
}

func TestCachedDialer_NoPinKeyOwnsIndependentSessions(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL}

	const callers = 8
	results := make(chan error, callers)
	for range callers {
		go func() {
			up, err := dialer.Connect(context.Background(), target)
			if err == nil {
				_, err = up.ListTools(context.Background())
				up.Close(context.Background())
			}
			results <- err
		}()
	}
	for range callers {
		if err := <-results; err != nil {
			t.Fatalf("connect/list: %v", err)
		}
	}
	if got := upstream.inits.Load(); got != callers {
		t.Fatalf("initializes = %d, want %d independent sessions", got, callers)
	}
	if got := upstream.discovers.Load(); got != 0 {
		t.Fatalf("server/discover reached legacy upstream %d times", got)
	}
}

func TestCachedDialer_ConcurrentColdConnectUsesOneSession(t *testing.T) {
	t.Parallel()

	var initializes atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})

	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				if initializes.Add(1) == 1 {
					close(started)
				}
				<-release
			}
			return next(ctx, method, req)
		}
	})
	inner := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil)
	srv := httptest.NewServer(inner)
	defer srv.Close()

	dialer := newCachedDialer()
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := dialer.Connect(context.Background(),
				appmcp.Target{URL: srv.URL, PinKey: "gw:consumer:reg"})
			results <- err
		}()
	}
	<-started
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("connect: %v", err)
		}
	}
	if got := initializes.Load(); got != 1 {
		t.Fatalf("initializes = %d, want 1", got)
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
	if got := upstream.discovers.Load(); got != 0 {
		t.Fatalf("server/discover reached legacy upstream %d times", got)
	}
}

func TestCachedDialer_URLChangeGetsNewSession(t *testing.T) {
	t.Parallel()

	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	for _, path := range []string{"/registry-a", "/registry-b", "/registry-a"} {
		up, err := dialer.Connect(context.Background(), appmcp.Target{
			URL:    upstream.srv.URL + path,
			PinKey: "gw:consumer:reg:user",
		})
		if err != nil {
			t.Fatalf("connect %s: %v", path, err)
		}
		if _, err := up.ListTools(context.Background()); err != nil {
			t.Fatalf("list %s: %v", path, err)
		}
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("initializes = %d, want distinct sessions for two URL identities", got)
	}
}

func TestCachedDialer_ProtocolModeChangeGetsNewSession(t *testing.T) {
	t.Parallel()

	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	for _, mode := range []registrydomain.MCPProtocolMode{
		registrydomain.MCPProtocolModeLegacy,
		registrydomain.MCPProtocolModeAuto,
		registrydomain.MCPProtocolModeLegacy,
	} {
		up, err := dialer.Connect(context.Background(), appmcp.Target{
			URL:          upstream.srv.URL,
			PinKey:       "gw:consumer:reg:user",
			ProtocolMode: mode,
		})
		if err != nil {
			t.Fatalf("connect mode %q: %v", mode, err)
		}
		if _, err := up.ListTools(context.Background()); err != nil {
			t.Fatalf("list mode %q: %v", mode, err)
		}
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("initializes = %d, want distinct sessions for two protocol modes", got)
	}
}

func TestCachedDialer_RefreshLogIsSanitized(t *testing.T) {
	t.Parallel()

	upstream := newUpstreamStub(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	dialer := mcpclient.NewCachedDialer(mcpclient.New(), logger)
	const secret = "refresh-secret-sentinel"
	up, err := dialer.Connect(context.Background(), appmcp.Target{
		URL:     upstream.srv.URL + "/mcp?token=" + secret,
		PinKey:  "gw:consumer:reg:user",
		Headers: map[string]string{"Authorization": "Bearer " + secret},
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := up.ListTools(context.Background()); err != nil {
		t.Fatalf("initial list: %v", err)
	}
	var failing http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Mcp-Session-Id") != "" {
			http.Error(w, "session missing", http.StatusNotFound)
			return
		}
		http.Error(w, "unavailable", http.StatusInternalServerError)
	})
	upstream.handler.Store(&failing)
	if _, err := up.ListTools(context.Background()); err == nil {
		t.Fatal("list after session loss unexpectedly succeeded")
	}
	output := logs.String()
	if bytes.Contains([]byte(output), []byte(secret)) {
		t.Fatalf("refresh log exposed secret: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte(`"category":"unreachable"`)) {
		t.Fatalf("refresh log missing sanitized category: %s", output)
	}
	if bytes.Contains([]byte(output), []byte(`"error"`)) {
		t.Fatalf("refresh log contains raw error attribute: %s", output)
	}
}
