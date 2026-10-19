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

package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// An application key, naming no end user, on a consumer with no registries.
// Listing must succeed — an empty tool list plus the gateway meta-tools — and
// a name that is not one of those tools is unknown. Nothing is dialed.
func TestHandler_AppWithNoRegistries_InitializeListsEmptyAndUnknownCall(t *testing.T) {
	t.Parallel()
	var dials atomic.Int32
	composer := appmcp.NewComposer(
		appmcp.DialerFunc(func(context.Context, appmcp.Target) (appmcp.Upstream, error) {
			dials.Add(1)
			return nil, errors.New("dialed")
		}),
		nil,
		newEmptySurfaceCache(),
		slog.New(slog.DiscardHandler),
	)
	inventory, err := appmcp.NewInventoryTool(composer, nil)
	if err != nil {
		t.Fatalf("inventory tool: %v", err)
	}

	authID := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "virtual",
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
		AuthIDs:   []ids.AuthID{authID},
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{{Consumer: cons}})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = identity.WithPrincipal(ctx, &identity.Principal{
			Subject: "app-key",
			Method:  identity.MethodAPIKey,
		})
		c.SetUserContext(ctx)
		return c.Next()
	})
	gateway := mcphttp.NewRPCGateway(composer, noopRunner(), nil).WithInventoryTool(inventory)
	app.Post(mcpPath, mcphttp.NewHandler(gateway, nil).Handle)

	status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("initialize status = %d", status)
	}
	if body["error"] != nil {
		t.Fatalf("initialize error = %v, want a successful handshake", body["error"])
	}
	result, _ := body["result"].(map[string]any)
	if result["protocolVersion"] != "2025-03-26" {
		t.Fatalf("protocolVersion = %v, want the requested revision", result["protocolVersion"])
	}

	status, body = rpcCall(t, app, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if status != fiber.StatusOK {
		t.Fatalf("tools/list status = %d", status)
	}
	if body["error"] != nil {
		t.Fatalf("tools/list error = %v, want an empty surface", body["error"])
	}
	names := toolNamesFromResult(t, body)
	if len(names) != 1 || names[0] != appmcp.InventoryToolName {
		t.Fatalf("tools = %v, want only %s", names, appmcp.InventoryToolName)
	}

	status, body = rpcCall(t, app, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+appmcp.InventoryToolName+`"}}`)
	if status != fiber.StatusOK || body["error"] != nil {
		t.Fatalf("inventory call status = %d error = %v", status, body["error"])
	}
	listed, err := json.Marshal(body["result"])
	if err != nil {
		t.Fatalf("encode inventory result: %v", err)
	}
	if !strings.Contains(string(listed), "You have no MCP servers on your surface.") {
		t.Fatalf("inventory = %s, want an empty server list", listed)
	}

	status, body = rpcCall(t, app, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ghost"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("tools/call status = %d, want 200 so the client parses the JSON-RPC error", status)
	}
	rpcErr, _ := body["error"].(map[string]any)
	if rpcErr["code"] != float64(-32602) {
		t.Fatalf("code = %v, want -32602", rpcErr["code"])
	}
	if rpcErr["message"] != "Unknown tool: ghost" {
		t.Fatalf("message = %v, want Unknown tool: ghost", rpcErr["message"])
	}

	// A named resource is still a routing failure: nothing was attached, and
	// the empty list does not invent a target.
	status, body = rpcCall(t, app, `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file://missing"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("resources/read status = %d", status)
	}
	rpcErr, _ = body["error"].(map[string]any)
	if rpcErr["code"] != float64(-32600) {
		t.Fatalf("resources/read code = %v, want -32600", rpcErr["code"])
	}

	if got := dials.Load(); got != 0 {
		t.Fatalf("upstream dials = %d, want 0", got)
	}
}

func toolNamesFromResult(t *testing.T, body map[string]any) []string {
	t.Helper()
	result, _ := body["result"].(map[string]any)
	raw, _ := result["tools"].([]any)
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		tool, _ := item.(map[string]any)
		name, _ := tool["name"].(string)
		names = append(names, name)
	}
	return names
}

type emptySurfaceCache struct {
	mu sync.Mutex
	m  map[string]any
}

func newEmptySurfaceCache() *emptySurfaceCache {
	return &emptySurfaceCache{m: map[string]any{}}
}

func (c *emptySurfaceCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return v, ok
}

func (c *emptySurfaceCache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = value
}

func (c *emptySurfaceCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}
