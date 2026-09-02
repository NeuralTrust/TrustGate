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
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
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

	handler := NewHandler(nil, nil, vault)
	handler.timings = streamTimings{
		poll:      10 * time.Millisecond,
		keepAlive: 20 * time.Millisecond,
		lifetime:  5 * time.Second,
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
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })

	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Contains(t, response.Header.Get("Content-Type"), "text/event-stream")

	frames := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(response.Body)
		var seen strings.Builder
		for {
			line, err := reader.ReadString('\n')
			seen.WriteString(line)
			if strings.Contains(seen.String(), "notifications/tools/list_changed") {
				frames <- seen.String()
				return
			}
			if err != nil {
				frames <- seen.String()
				return
			}
		}
	}()

	// Nothing has changed yet, so the stream must stay quiet.
	select {
	case body := <-frames:
		t.Fatalf("stream pushed before anything changed: %q", body)
	case <-time.After(100 * time.Millisecond):
	}

	vault.link()

	select {
	case body := <-frames:
		require.Contains(t, body, "notifications/tools/list_changed")
		require.Contains(t, body, "event: message")
	case <-time.After(5 * time.Second):
		t.Fatal("no tools/list_changed frame arrived after the account was connected")
	}
}
