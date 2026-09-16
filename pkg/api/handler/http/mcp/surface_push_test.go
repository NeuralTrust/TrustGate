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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

// The GET notification stream only carries tools/list_changed while the client
// holds it open, and not every client does. These cover the other route: a POST
// the client is already waiting for answers as a short stream carrying both the
// result and the notification, so the tool list refreshes without anyone
// pressing "Refresh tools list" by hand.
func TestPostAnnouncesASurfaceChangeTheClientMissed(t *testing.T) {
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

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice", Method: identity.MethodJWT})
		c.SetUserContext(ctx)
		return c.Next()
	})
	// The tail of Handle: dispatch happens upstream, the announcement is decided
	// on the way out.
	app.Post("/*", func(c *fiber.Ctx) error {
		rc, resolveErr := resolveMCPConsumer(c)
		if resolveErr != nil {
			return resolveErr
		}
		return writeRPCBody(c, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: fiber.Map{}},
			handler.surfaceMoved(c, rc))
	})

	call := func(accept string) (int, string, string) {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/virtual/mcp", nil)
		request.Header.Set("Accept", accept)
		response, testErr := app.Test(request)
		require.NoError(t, testErr)
		defer func() { _ = response.Body.Close() }()
		body, readErr := io.ReadAll(response.Body)
		require.NoError(t, readErr)
		return response.StatusCode, response.Header.Get("Content-Type"), string(body)
	}

	const bothTypes = "application/json, text/event-stream"

	// Nothing seen before is not a change: there is nothing the client could
	// have missed.
	status, contentType, body := call(bothTypes)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, contentType, fiber.MIMEApplicationJSON)
	require.NotContains(t, body, "list_changed")

	// The user finishes the connect in a browser; the MCP session knows nothing
	// about it until its next request.
	vault.link()
	// The watch snapshot is cached for a few seconds, and what is under test
	// here is the memory of what this caller was last told, not that cache —
	// which the stream tests already exercise over a real connection. A fresh
	// watcher reads the linked vault now instead of making the suite wait.
	handler.surface = appmcp.NewSurfaceWatcher(vault, nil)

	status, contentType, body = call(bothTypes)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, contentType, eventStreamContentType)
	require.Contains(t, body, `"jsonrpc":"2.0"`)
	require.Contains(t, body, "notifications/tools/list_changed")

	// Announced once: the surface has not moved again.
	_, contentType, body = call(bothTypes)
	require.Contains(t, contentType, fiber.MIMEApplicationJSON)
	require.NotContains(t, body, "list_changed")
}

func TestPostKeepsJSONForAClientThatOnlyAsksForJSON(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	consumer := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
		AuthIDs:   []ids.AuthID{authID},
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{{Consumer: consumer}})
	vault := &streamVault{}
	handler := NewHandler(nil, appmcp.NewSurfaceWatcher(vault, nil))

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice", Method: identity.MethodJWT})
		c.SetUserContext(ctx)
		return c.Next()
	})
	app.Post("/*", func(c *fiber.Ctx) error {
		rc, resolveErr := resolveMCPConsumer(c)
		if resolveErr != nil {
			return resolveErr
		}
		return writeRPCBody(c, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: fiber.Map{}},
			handler.surfaceMoved(c, rc))
	})

	post := func() *http.Response {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/virtual/mcp", nil)
		request.Header.Set("Accept", fiber.MIMEApplicationJSON)
		response, testErr := app.Test(request)
		require.NoError(t, testErr)
		return response
	}

	first := post()
	require.NoError(t, first.Body.Close())
	vault.link()
	second := post()
	defer func() { _ = second.Body.Close() }()
	body, err := io.ReadAll(second.Body)
	require.NoError(t, err)
	// A client that never said it reads streams is never handed one, whatever
	// changed underneath it.
	require.Contains(t, second.Header.Get("Content-Type"), fiber.MIMEApplicationJSON)
	require.NotContains(t, string(body), "list_changed")
}

func TestSurfaceMemoryForgetsTheOldestWhenFull(t *testing.T) {
	memory := newSurfaceMemory()
	require.False(t, memory.moved("a", "one"), "a first sighting is not a change")
	require.True(t, memory.moved("a", "two"))
	require.False(t, memory.moved("a", "two"))
	require.False(t, memory.moved("", "two"), "an unidentifiable caller is never announced to")
	require.False(t, memory.moved("a", ""), "an unreadable surface is not a change")

	for i := 0; i < maxSurfaceMemoryEntries; i++ {
		memory.moved(string(rune(i))+"-key", "one")
	}
	require.Len(t, memory.seen, maxSurfaceMemoryEntries)
	// "a" was the oldest, so it was dropped: its next call starts over rather
	// than announcing a change against a snapshot nobody kept.
	require.False(t, memory.moved("a", "three"))
}

// storeInstallations serves one caller's Store installs, growing when the user
// installs a server from the catalog.
type storeInstallations struct {
	mu      sync.Mutex
	servers []string
}

func (s *storeInstallations) add(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers = append(s.servers, code)
}

func (s *storeInstallations) ListByPrincipal(
	context.Context,
	ids.GatewayID,
	string,
) ([]*installationdomain.Installation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*installationdomain.Installation, 0, len(s.servers))
	for i, code := range s.servers {
		out = append(out, &installationdomain.Installation{
			CatalogCode: code,
			Status:      installationdomain.StatusInstalled,
			UpdatedAt:   time.Date(2026, 9, 16, 12, i, 0, 0, time.UTC),
		})
	}
	return out, nil
}

// The MCP Store's consumer is synthetic: it holds no registries, because its
// servers are resolved per caller at dispatch. The version reported in
// server/discover and initialize was hashed from the consumer's own record, so
// on the Store it was one unchanging string — for every caller, and for every
// install they ever made. A client that keys its cached tool list on it, which
// is what a server/discover probe is for, had no reason to ever re-list.
func TestStoreSurfaceVersionMovesWithAnInstall(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	installs := &storeInstallations{}

	version := func() string {
		// A fresh watcher per read: the snapshot is cached for a few seconds and
		// what is under test is what the version is derived from, not that cache.
		handler := NewHandler(nil, appmcp.NewSurfaceWatcher(&streamVault{}, installs))
		store := consumerdomain.BuildStoreConsumer(gwID)
		data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{{Consumer: store}})

		app := fiber.New(fiber.Config{DisableStartupMessage: true})
		app.Use(func(c *fiber.Ctx) error {
			ctx := appconsumer.WithAuthID(c.UserContext(), authID)
			ctx = appconsumer.WithData(ctx, data)
			ctx = appconsumer.WithGatewayID(ctx, gwID)
			ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice", Method: identity.MethodJWT})
			c.SetUserContext(ctx)
			return c.Next()
		})
		var out string
		app.Post("/*", func(c *fiber.Ctx) error {
			rc, err := resolveMCPConsumer(c)
			if err != nil {
				return err
			}
			out = handler.surfaceVersion(c, rc)
			return c.SendStatus(fiber.StatusOK)
		})
		response, err := app.Test(httptest.NewRequest(http.MethodPost, "/store/mcp", nil))
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		return out
	}

	empty := version()
	installs.add("com.notion/mcp")
	withNotion := version()
	installs.add("com.linear/mcp")
	withLinear := version()

	require.NotEqual(t, empty, withNotion, "installing a server must move the version")
	require.NotEqual(t, withNotion, withLinear, "installing a second server must move it again")
}
