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
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

// streamVault serves the caller's credentials and starts returning a linked
// provider once linkNow is called, standing in for a user finishing the connect
// flow in a browser while the MCP session stays open.
type streamVault struct {
	mu     sync.Mutex
	linked bool
}

func (v *streamVault) link() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.linked = true
}

func (v *streamVault) Upsert(context.Context, *vaultdomain.Credential) error { return nil }

func (v *streamVault) Find(context.Context, ids.GatewayID, string, string) (*vaultdomain.Credential, error) {
	return nil, vaultdomain.ErrNotFound
}

func (v *streamVault) ListByPrincipal(
	context.Context,
	ids.GatewayID,
	string,
) ([]*vaultdomain.Credential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.linked {
		return nil, nil
	}
	return []*vaultdomain.Credential{{
		Provider:  "linear",
		UpdatedAt: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
	}}, nil
}

func (v *streamVault) Delete(context.Context, ids.GatewayID, string, string) error { return nil }

// TestStreamPushesListChangedOverRealConnection exercises the stream over a real
// socket rather than fiber's in-memory test helper, because the whole point is
// that frames reach the client while the response is still open.
func TestStreamPushesListChangedOverRealConnection(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	linear, err := registrydomain.NewMCPRegistry(gwID, "linear", "", &registrydomain.MCPTarget{
		URL: "https://linear.example.com/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "linear",
			ClientID:     "cid",
			AuthorizeURL: "https://linear.example.com/authorize",
			TokenURL:     "https://linear.example.com/token",
		},
	})
	require.NoError(t, err)
	consumer := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
		AuthIDs:   []ids.AuthID{authID},
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: consumer, Registries: []*registrydomain.Registry{linear}},
	})
	vault := &streamVault{}

	handler := NewHandler(nil, appmcp.NewSurfaceWatcher(vault, nil))
	handler.timings = streamTimings{
		poll:      10 * time.Millisecond,
		keepAlive: 20 * time.Millisecond,
		lifetime:  12 * time.Second,
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice", Method: identity.MethodJWT})
		c.SetUserContext(ctx)
		return c.Next()
	})
	app.Get("/*", handler.Stream)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = app.Listener(listener) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/virtual/mcp", nil)
	require.NoError(t, err)
	request.Header.Set("Accept", "text/event-stream")
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })

	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, response.Header.Get("Content-Type"), "text/event-stream")

	frames := make(chan string, 2)
	go collectListChangedFrames(response.Body, 2, frames)

	select {
	case body := <-frames:
		require.Contains(t, body, "notifications/tools/list_changed")
		require.Contains(t, body, "event: message")
	case <-time.After(5 * time.Second):
		t.Fatal("no tools/list_changed frame arrived when the stream opened")
	}

	vault.link()

	select {
	case body := <-frames:
		require.Equal(t, 2, strings.Count(body, "notifications/tools/list_changed"))
	case <-time.After(8 * time.Second):
		t.Fatal("no tools/list_changed frame arrived after the account was connected")
	}
}

type mutatingConsumerFinder struct {
	mu   sync.Mutex
	data *appconsumer.Data
}

func (f *mutatingConsumerFinder) FindByGateway(context.Context, ids.GatewayID) (*appconsumer.Data, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data, nil
}

func (f *mutatingConsumerFinder) replace(data *appconsumer.Data) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data = data
}

func TestStreamPushesListChangedWhenRegistryIsAttached(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	linear, err := registrydomain.NewMCPRegistry(gwID, "linear", "", &registrydomain.MCPTarget{
		URL: "https://linear.example.com/mcp",
	})
	require.NoError(t, err)
	notion, err := registrydomain.NewMCPRegistry(gwID, "notion", "", &registrydomain.MCPTarget{
		URL: "https://mcp.notion.com/mcp",
	})
	require.NoError(t, err)
	consumer := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
		AuthIDs:   []ids.AuthID{authID},
	}
	opened := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: consumer, Registries: []*registrydomain.Registry{linear}},
	})
	finder := &mutatingConsumerFinder{data: opened}

	handler := NewHandler(nil, appmcp.NewSurfaceWatcher(nil, nil), WithConsumerFinder(finder))
	handler.timings = streamTimings{
		poll:      10 * time.Millisecond,
		keepAlive: 20 * time.Millisecond,
		lifetime:  5 * time.Second,
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithGatewayID(ctx, gwID)
		ctx = appconsumer.WithData(ctx, opened)
		ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice", Method: identity.MethodJWT})
		c.SetUserContext(ctx)
		return c.Next()
	})
	app.Get("/*", handler.Stream)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = app.Listener(listener) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/virtual/mcp", nil)
	require.NoError(t, err)
	request.Header.Set("Accept", "text/event-stream")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })
	require.Equal(t, http.StatusOK, response.StatusCode)

	frames := make(chan string, 2)
	go collectListChangedFrames(response.Body, 2, frames)

	select {
	case <-frames:
	case <-time.After(5 * time.Second):
		t.Fatal("no tools/list_changed frame arrived when the stream opened")
	}

	finder.replace(appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: consumer, Registries: []*registrydomain.Registry{linear, notion}},
	}))

	select {
	case body := <-frames:
		require.Equal(t, 2, strings.Count(body, "notifications/tools/list_changed"))
	case <-time.After(5 * time.Second):
		t.Fatal("no tools/list_changed frame arrived after Notion was attached")
	}
}

func collectListChangedFrames(r io.Reader, want int, frames chan<- string) {
	reader := bufio.NewReader(r)
	var seen strings.Builder
	count := 0
	for {
		line, err := reader.ReadString('\n')
		seen.WriteString(line)
		next := strings.Count(seen.String(), "notifications/tools/list_changed")
		if next > count {
			count = next
			frames <- seen.String()
			if count >= want {
				return
			}
		}
		if err != nil {
			frames <- seen.String()
			return
		}
	}
}

// newListenApp builds the gateway a 2026-07-28 client talks to: one POST
// endpoint, one consumer bound to a server whose account the user has not
// connected yet, and a vault that can be made to report the connection.
func newListenApp(t *testing.T) (*fiber.App, *streamVault) {
	t.Helper()
	gwID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	linear, err := registrydomain.NewMCPRegistry(gwID, "linear", "", &registrydomain.MCPTarget{
		URL: "https://linear.example.com/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "linear",
			ClientID:     "cid",
			AuthorizeURL: "https://linear.example.com/authorize",
			TokenURL:     "https://linear.example.com/token",
		},
	})
	require.NoError(t, err)
	consumer := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
		AuthIDs:   []ids.AuthID{authID},
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: consumer, Registries: []*registrydomain.Registry{linear}},
	})
	vault := &streamVault{}

	handler := NewHandler(nil, appmcp.NewSurfaceWatcher(vault, nil))
	handler.timings = streamTimings{
		poll:      10 * time.Millisecond,
		keepAlive: 20 * time.Millisecond,
		lifetime:  12 * time.Second,
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice", Method: identity.MethodJWT})
		c.SetUserContext(ctx)
		return c.Next()
	})
	app.Post("/*", handler.Handle)
	return app, vault
}

// A 2026-07-28 client has no GET stream to open: it asks for the change
// notifications it wants on a subscriptions/listen request and reads them off
// that response while it stays open. This exercises it over a real socket,
// because the whole point is that frames arrive before the response ends.
func TestSubscriptionsListenPushesListChangedOverRealConnection(t *testing.T) {
	app, vault := newListenApp(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = app.Listener(listener) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	body := `{"jsonrpc":"2.0","id":42,"method":"subscriptions/listen",` +
		`"params":{"notifications":{"toolsListChanged":true,"promptsListChanged":true}}}`
	request, err := http.NewRequest(
		http.MethodPost, "http://"+listener.Addr().String()+"/virtual/mcp", strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })

	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, response.Header.Get("Content-Type"), "text/event-stream")

	frames := make(chan string, 2)
	go collectListChangedFrames(response.Body, 2, frames)

	select {
	case seen := <-frames:
		require.Contains(t, seen, "notifications/subscriptions/acknowledged")
		require.Less(t,
			strings.Index(seen, "notifications/subscriptions/acknowledged"),
			strings.Index(seen, "notifications/tools/list_changed"),
			"a notification must not arrive before the subscription is acknowledged")
		require.Contains(t, seen, `"toolsListChanged":true`)
		require.NotContains(t, seen, "promptsListChanged",
			"the ack names only what the gateway agreed to send, and it sends no prompt changes")
		require.Contains(t, seen, `"io.modelcontextprotocol/subscriptionId":42`,
			"every frame must carry the id of the request that opened the stream")
	case <-time.After(5 * time.Second):
		t.Fatal("no acknowledgement or notification arrived when the stream opened")
	}

	vault.link()

	select {
	case seen := <-frames:
		require.Equal(t, 2, strings.Count(seen, "notifications/tools/list_changed"),
			"connecting an account gives the user tools, which the stream must announce")
	case <-time.After(8 * time.Second):
		t.Fatal("no tools/list_changed frame arrived after the account was connected")
	}
}

// A client that opts into nothing this gateway sends gets an answer instead of
// a connection held open to deliver silence.
func TestSubscriptionsListenWithoutAnHonoredTypeAnswersAtOnce(t *testing.T) {
	t.Parallel()
	app, _ := newListenApp(t)

	request := httptest.NewRequest(http.MethodPost, "/virtual/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"notifications":{"promptsListChanged":true}}}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request, 5000)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()

	require.Equal(t, fiber.StatusOK, response.StatusCode)
	payload, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(payload, &decoded))
	result, _ := decoded["result"].(map[string]any)
	require.NotNil(t, result, "body = %s", payload)
	require.Equal(t, "complete", result["resultType"])
	meta, _ := result["_meta"].(map[string]any)
	require.Equal(t, float64(7), meta[subscriptionIDMetaKey],
		"the result closes the subscription the request opened, so it names it")
}
