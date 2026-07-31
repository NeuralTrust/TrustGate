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
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
)

const mcpPath = "/virtual/mcp"

func newApp(t *testing.T, composer appmcp.Composer, consumerType consumerdomain.Type, authorized bool) *fiber.App {
	t.Helper()
	return newAppWithRunner(t, composer, noopRunner(), consumerType, authorized)
}

func noopRunner() *appmcp.PluginRunner {
	return appmcp.NewPluginRunner(nil, discardLogger())
}

func newAppWithRunner(t *testing.T, composer appmcp.Composer, plugins *appmcp.PluginRunner, consumerType consumerdomain.Type, authorized bool) *fiber.App {
	t.Helper()
	return newAppWithRunnerAndLimiter(t, composer, plugins, nil, consumerType, authorized)
}

func newAppWithRunnerAndLimiter(t *testing.T, composer appmcp.Composer, plugins *appmcp.PluginRunner, limiter ratelimitapp.Checker, consumerType consumerdomain.Type, authorized bool) *fiber.App {
	t.Helper()
	authID := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "virtual",
		Type:      consumerType,
		Slug:      "virtual",
		Active:    true,
	}
	if authorized {
		cons.AuthIDs = []ids.AuthID{authID}
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{{Consumer: cons}})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandler(mcphttp.NewRPCGateway(composer, plugins, limiter), appmcp.NewRoleScoper(approle.NewOIDCResolver()))
	app.Post(mcpPath, handler.Handle)
	app.Get(mcpPath, handler.MethodNotAllowed)
	return app
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func rpcCall(t *testing.T, app *fiber.App, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, mcpPath, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	var decoded map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	return res.StatusCode, decoded
}

func TestHandler_DefaultIdP_AllowedWithoutAttachedAuth(t *testing.T) {
	t.Parallel()
	// An MCP consumer with no identity provider of its own (empty AuthIDs)
	// authenticated via the built-in NeuralTrust default IdP: the resolved
	// AuthID is the well-known default sentinel, which the handler must accept
	// even though it is not attached to the consumer.
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "virtual",
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
	}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{{Consumer: cons}})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), appauth.DefaultIdPAuthID())
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandler(mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil), appmcp.NewRoleScoper(approle.NewOIDCResolver()))
	app.Post(mcpPath, handler.Handle)

	status, _ := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("status = %d, want 200 (default IdP must be accepted for a consumer with no attached auth)", status)
	}
}

func TestHandler_Initialize_EchoesSupportedVersion(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("status = %d", status)
	}
	result := body["result"].(map[string]any)
	if result["protocolVersion"] != "2025-03-26" {
		t.Fatalf("protocolVersion = %v, want echo of requested", result["protocolVersion"])
	}
}

func TestHandler_Initialize_UnknownVersionFallsBackToLatest(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	_, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	result := body["result"].(map[string]any)
	if result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocolVersion = %v, want latest", result["protocolVersion"])
	}
}

func TestHandler_ToolsList_ComposedSurface(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{{Name: "gh_search"}}, nil).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)

	status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	if status != fiber.StatusOK {
		t.Fatalf("status = %d", status)
	}
	tools := body["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "gh_search" {
		t.Fatalf("tools = %v", tools)
	}
}

func TestHandler_ToolsCall_PassesUpstreamRPCErrorThrough(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, "boom", mock.Anything).
		Return(nil, &appmcp.RPCError{Code: -32099, Message: "upstream exploded"}).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)

	status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"boom"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("JSON-RPC errors must ride on HTTP 200, got %d", status)
	}
	rpcErr := body["error"].(map[string]any)
	if rpcErr["code"].(float64) != -32099 || rpcErr["message"] != "upstream exploded" {
		t.Fatalf("error = %v, want upstream error verbatim", rpcErr)
	}
}

// The consent refusal must reach the agent, so it rides on HTTP 200 carrying
// the JSON-RPC error and the connect URL. Any 4xx here is read by MCP clients
// as a transport failure: they drop the connection and restart authentication
// without ever parsing the body.
func TestHandler_ToolsCall_ConsentRequiredRidesOn200(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, "notion-search", mock.Anything).
		Return(nil, &appmcp.ConsentRequiredError{
			Provider: "com.notion/mcp", Ticket: "tk", Path: "/virtual/mcp",
		}).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)

	status, body := rpcCall(t, app,
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"notion-search"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("status = %d, want 200 so the client parses the JSON-RPC error", status)
	}
	rpcErr := body["error"].(map[string]any)
	if rpcErr["code"].(float64) != -32003 {
		t.Fatalf("code = %v, want -32003", rpcErr["code"])
	}
	data := rpcErr["data"].(map[string]any)
	if data["provider"] != "com.notion/mcp" {
		t.Fatalf("provider = %v", data["provider"])
	}
	connectURL, _ := data["connect_url"].(string)
	if !strings.Contains(connectURL, "/virtual/mcp/connect?ticket=tk") {
		t.Fatalf("connect_url = %q, want the consumer's connect page", connectURL)
	}
}

// A tool the toolkit forbids is reported to the agent as a policy denial over
// HTTP 200, so the client surfaces the reason instead of failing the transport.
func TestHandler_ToolsCall_ToolNotPermittedRidesOn200(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, "notion-search", mock.Anything).
		Return(nil, &appmcp.ToolNotPermittedError{Tool: "notion-search"}).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)

	status, body := rpcCall(t, app,
		`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"notion-search"}}`)
	if status != fiber.StatusOK {
		t.Fatalf("status = %d, want 200 so the client parses the JSON-RPC error", status)
	}
	rpcErr := body["error"].(map[string]any)
	if rpcErr["code"].(float64) != -32001 {
		t.Fatalf("code = %v, want the policy-blocked code", rpcErr["code"])
	}
	if msg, _ := rpcErr["message"].(string); !strings.Contains(msg, "not permitted") {
		t.Fatalf("message = %q, want it to say the tool is not permitted", msg)
	}
}

func TestHandler_UnknownMethod_MapsToMethodNotFound(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	_, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":3,"method":"tools/subscribe"}`)
	if code := body["error"].(map[string]any)["code"].(float64); code != -32601 {
		t.Fatalf("code = %v, want -32601 method not found", code)
	}
}

func TestHandler_Notification_Returns202(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	status, _ := rpcCall(t, app, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if status != fiber.StatusAccepted {
		t.Fatalf("status = %d, want 202", status)
	}
}

func TestHandler_ParseError(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	_, body := rpcCall(t, app, `{not json`)
	if code := body["error"].(map[string]any)["code"].(float64); code != -32700 {
		t.Fatalf("code = %v, want -32700 parse error", code)
	}
}

func TestHandler_CredentialNotAllowed_Forbidden(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, false)
	status, _ := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if status != fiber.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a credential not attached to the consumer", status)
	}
}

func TestHandler_NonMCPConsumer_NotFound(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeLLM, true)
	status, _ := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if status != fiber.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a non-MCP consumer", status)
	}
}

func TestHandler_GETIs405(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	req := httptest.NewRequest(fiber.MethodGet, mcpPath, nil)
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != fiber.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 (anything else loops MCP clients)", res.StatusCode)
	}
	if allow := res.Header.Get(fiber.HeaderAllow); allow != fiber.MethodPost {
		t.Fatalf("Allow = %q, want POST", allow)
	}
}
