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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const mcpPath = "/virtual/mcp"

func newApp(t *testing.T, composer appmcp.Composer, consumerType consumerdomain.Type, authorized bool) *fiber.App {
	t.Helper()
	return newAppWithRunner(t, composer, noopRunner(), consumerType, authorized)
}

func newAppWithoutConsumers(t *testing.T) *fiber.App {
	t.Helper()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(ids.New[ids.GatewayKind](), nil)
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandler(
		mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil),
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
	)
	app.Post(mcpPath, handler.Handle)
	return app
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
	return newAppWithGateway(t, mcphttp.NewRPCGateway(composer, plugins, limiter), consumerType, authorized)
}

func newAppWithGateway(t *testing.T, gateway *mcphttp.RPCGateway, consumerType consumerdomain.Type, authorized bool) *fiber.App {
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
	handler := mcphttp.NewHandler(gateway, appmcp.NewRoleScoper(approle.NewOIDCResolver()))
	app.Post(mcpPath, handler.Handle)
	app.Get(mcpPath, handler.MethodNotAllowed)
	app.Delete(mcpPath, handler.MethodNotAllowed)
	return app
}

func newAppWithRegistries(t *testing.T, apps appmcp.AppsMediator, registries ...*registrydomain.Registry) *fiber.App {
	t.Helper()
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
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: cons, Registries: registries},
	})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandlerWithApps(
		mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil),
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
		mcphttp.MRTRSupport{},
		mcphttp.TasksSupport{},
		mcphttp.SubscriptionsSupport{},
		apps,
	)
	app.Post(mcpPath, handler.Handle)
	return app
}

type recordingAppsMediator struct{ calls atomic.Int32 }

func (m *recordingAppsMediator) Advertise(_ context.Context, _ bool, _ *appconsumer.RoutableConsumer, client appmcp.MCPAppsClientCapability) bool {
	m.calls.Add(1)
	return len(client.MIMETypes) == 1 && client.MIMETypes[0] == appmcp.MCPAppsHTMLMIMEType
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func rpcCall(t *testing.T, app *fiber.App, body string) (int, map[string]any) {
	t.Helper()
	return rpcCallWithHeaders(t, app, body, nil)
}

func rpcCallWithHeaders(t *testing.T, app *fiber.App, body string, headers http.Header) (int, map[string]any) {
	t.Helper()
	status, raw := rpcRawCallWithHeaders(t, app, body, headers)
	var decoded map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	return status, decoded
}

func rpcRawCallWithHeaders(t *testing.T, app *fiber.App, body string, headers http.Header) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, mcpPath, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, raw
}

func modernHeadersFor(method string) http.Header {
	return http.Header{
		"MCP-Protocol-Version": {"2026-07-28"},
		"Mcp-Method":           {method},
	}
}

func modernHeadersWithName(method, name string) http.Header {
	headers := modernHeadersFor(method)
	headers.Set("Mcp-Name", name)
	return headers
}

func TestHandler_UnsupportedTransportMethodsReturn405(t *testing.T) {
	t.Parallel()
	for _, method := range []string{fiber.MethodGet, fiber.MethodDelete} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
			res, err := app.Test(httptest.NewRequest(method, mcpPath, nil), -1)
			require.NoError(t, err)
			defer func() { _ = res.Body.Close() }()
			require.Equal(t, fiber.StatusMethodNotAllowed, res.StatusCode)
			require.Equal(t, fiber.MethodPost, res.Header.Get(fiber.HeaderAllow))
		})
	}
}

func containsHeaderAnnotation(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		if _, ok := current["x-mcp-header"]; ok {
			return true
		}
		for _, nested := range current {
			if containsHeaderAnnotation(nested) {
				return true
			}
		}
	case []any:
		for _, nested := range current {
			if containsHeaderAnnotation(nested) {
				return true
			}
		}
	}
	return false
}

func TestHandler_DefaultIdP_AllowedWithoutAttachedAuth(t *testing.T) {
	t.Parallel()
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
	var tool appmcp.Tool
	require.NoError(t, json.Unmarshal([]byte(`{
		"name":"gh_search",
		"inputSchema":{"type":"object","properties":{"query":{"type":"string","x-mcp-header":"X-Query"}}}
	}`), &tool))
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{tool}, nil).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)

	status, raw := rpcRawCallWithHeaders(t, app, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`, nil)
	require.Equal(t, fiber.StatusOK, status)
	require.Equal(
		t,
		`{"jsonrpc":"2.0","id":7,"result":{"tools":[{"inputSchema":{"type":"object","properties":{"query":{"type":"string","x-mcp-header":"X-Query"}}},"name":"gh_search"}]}}`,
		string(raw),
	)
}

func TestHandler_ToolsCall_PassesUpstreamRPCErrorThrough(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("boom")).
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

func TestHandler_RPCErrorSessionHeaderIsolationByEra(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		body           string
		requestHeaders http.Header
		sessionHeader  string
		wantSession    bool
	}{
		{
			name:          "legacy preserves session header",
			body:          `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"boom"}}`,
			sessionHeader: "mCp-SeSsIoN-iD",
			wantSession:   true,
		},
		{
			name:           "modern filters canonical casing",
			body:           `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"boom","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			requestHeaders: modernHeadersWithName("tools/call", "boom"),
			sessionHeader:  "Mcp-Session-Id",
		},
		{
			name:           "modern filters lowercase",
			body:           `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"boom","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			requestHeaders: modernHeadersWithName("tools/call", "boom"),
			sessionHeader:  "mcp-session-id",
		},
		{
			name:           "modern filters mixed casing",
			body:           `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"boom","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			requestHeaders: modernHeadersWithName("tools/call", "boom"),
			sessionHeader:  "mCp-SeSsIoN-iD",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			composer := mocks.NewComposer(t)
			composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("boom")).
				Return(nil, &appmcp.RPCError{
					Code:    -32099,
					Message: "upstream exploded",
					HTTPHeaders: http.Header{
						tc.sessionHeader: {"session-value"},
						"X-Upstream":     {"preserved"},
					},
				}).Once()
			app := newApp(t, composer, consumerdomain.TypeMCP, true)
			req := httptest.NewRequest(fiber.MethodPost, mcpPath, strings.NewReader(tc.body))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			for name, values := range tc.requestHeaders {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}
			res, err := app.Test(req, -1)
			require.NoError(t, err)
			defer func() { _ = res.Body.Close() }()
			require.Equal(t, "preserved", res.Header.Get("X-Upstream"))
			require.Equal(t, tc.wantSession, res.Header.Get("Mcp-Session-Id") == "session-value")
		})
	}
}

func TestHandler_ToolsCall_ConsentRequiredRidesOn200(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("notion-search")).
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

func TestHandler_ToolsCall_ToolNotPermittedRidesOn200(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("notion-search")).
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

func TestHandler_Initialize_VersionTracksTheToolSurface(t *testing.T) {
	t.Parallel()
	reg := func(name string) *registrydomain.Registry {
		r, err := registrydomain.NewMCPRegistry(
			ids.New[ids.GatewayKind](), name, "",
			&registrydomain.MCPTarget{URL: "https://" + name + ".example.com/mcp"},
		)
		if err != nil {
			t.Fatalf("registry: %v", err)
		}
		return r
	}
	notion, linear := reg("notion"), reg("linear")

	versionFor := func(regs ...*registrydomain.Registry) string {
		app := newAppWithRegistries(t, nil, regs...)
		_, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
		info := body["result"].(map[string]any)["serverInfo"].(map[string]any)
		return info["version"].(string)
	}

	one := versionFor(notion)
	if !strings.HasPrefix(one, "1.0+") {
		t.Fatalf("version = %q, want the implementation version plus a fingerprint", one)
	}
	if again := versionFor(notion); again != one {
		t.Fatalf("version is unstable for the same configuration: %q vs %q", one, again)
	}
	if versionFor(notion, linear) != versionFor(linear, notion) {
		t.Fatal("version must not depend on registry ordering")
	}
	if two := versionFor(notion, linear); two == one {
		t.Fatalf("version %q did not change after attaching a registry", two)
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
	status, raw := rpcRawCallWithHeaders(t, app, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
	if status != fiber.StatusAccepted {
		t.Fatalf("status = %d, want 202", status)
	}
	require.Empty(t, raw)
}

func TestHandler_ParseError(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	_, body := rpcCall(t, app, `{not json`)
	if code := body["error"].(map[string]any)["code"].(float64); code != -32700 {
		t.Fatalf("code = %v, want -32700 parse error", code)
	}
}

func TestHandler_ModernParseErrorUsesHTTP400(t *testing.T) {
	t.Parallel()
	app := newAppWithoutConsumers(t)
	status, body := rpcCallWithHeaders(t, app, `{not json`, http.Header{
		"MCP-Protocol-Version": {"2026-07-28"},
	})
	require.Equal(t, fiber.StatusBadRequest, status)
	require.Equal(t, float64(-32700), body["error"].(map[string]any)["code"])
}

func TestHandler_ModernNonObjectRequestsUseInvalidRequest(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{name: "array", body: `[]`},
		{name: "string", body: `"request"`},
		{name: "number", body: `1`},
		{name: "boolean", body: `true`},
		{name: "null", body: `null`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, response := rpcCallWithHeaders(t, newAppWithoutConsumers(t), tc.body, http.Header{
				"MCP-Protocol-Version": {"2026-07-28"},
			})
			require.Equal(t, fiber.StatusBadRequest, status)
			require.Contains(t, response, "id")
			require.Nil(t, response["id"])
			require.Equal(t, float64(-32600), response["error"].(map[string]any)["code"])
		})
	}
}

func TestHandler_UnknownProtocolPrecedesMalformedJSON(t *testing.T) {
	t.Parallel()
	app := newAppWithoutConsumers(t)
	status, body := rpcCallWithHeaders(t, app, `{not json`, http.Header{
		"MCP-Protocol-Version": {"2099-01-01"},
	})
	require.Equal(t, fiber.StatusBadRequest, status)
	rpcErr := body["error"].(map[string]any)
	require.Equal(t, float64(-32022), rpcErr["code"])
	require.Equal(t, "2099-01-01", rpcErr["data"].(map[string]any)["requested"])
	require.Equal(t, []any{"2026-07-28", "2025-06-18", "2025-03-26", "2024-11-05"}, rpcErr["data"].(map[string]any)["supported"])
}

func TestHandler_LegacyBoundaryErrorsPreserveLookupPrecedence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		app        func(*testing.T) *fiber.App
		body       string
		wantStatus int
	}{
		{
			name: "malformed JSON preserves forbidden",
			app: func(t *testing.T) *fiber.App {
				return newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, false)
			},
			body:       `{not json`,
			wantStatus: fiber.StatusForbidden,
		},
		{
			name:       "invalid request preserves not found",
			app:        newAppWithoutConsumers,
			body:       `{}`,
			wantStatus: fiber.StatusNotFound,
		},
		{
			name: "array preserves forbidden",
			app: func(t *testing.T) *fiber.App {
				return newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, false)
			},
			body:       `[]`,
			wantStatus: fiber.StatusForbidden,
		},
		{
			name:       "null preserves not found",
			app:        newAppWithoutConsumers,
			body:       `null`,
			wantStatus: fiber.StatusNotFound,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, _ := rpcCall(t, tc.app(t), tc.body)
			require.Equal(t, tc.wantStatus, status)
		})
	}
}

func TestHandler_LegacyInvalidRequestPreservesRoleScopePrecedence(t *testing.T) {
	t.Parallel()
	authID := ids.New[ids.AuthKind]()
	gatewayID := ids.New[ids.GatewayKind]()
	consumer := &consumerdomain.Consumer{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gatewayID,
		Name:        "virtual",
		Type:        consumerdomain.TypeMCP,
		Slug:        "virtual",
		Active:      true,
		AuthIDs:     []ids.AuthID{authID},
		RoutingMode: consumerdomain.RoutingModeRoleBased,
	}
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{{Consumer: consumer}})
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
	roleScoper := mocks.NewRoleScoper(t)
	roleScoper.EXPECT().Scope(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, appmcp.ErrNoRoleAccess).Once()
	handler := mcphttp.NewHandler(
		mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil),
		roleScoper,
	)
	app.Post(mcpPath, handler.Handle)
	status, _ := rpcCall(t, app, `{}`)
	require.Equal(t, fiber.StatusForbidden, status)
}

func TestHandler_ModernNotificationReturns202WithoutBody(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	body := `{"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, raw := rpcRawCallWithHeaders(t, app, body, modernHeadersFor("tools/list"))
	require.Equal(t, fiber.StatusAccepted, status)
	require.Empty(t, raw)
}

func TestHandler_UnknownModernNotificationSkipsDownstreamEffects(t *testing.T) {
	t.Parallel()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(ids.New[ids.GatewayKind](), nil)
	requestTrace := trace.New("notification", trace.Metadata{Kind: events.KindMCP})
	var metricsSkipped bool

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = trace.NewContext(ctx, requestTrace)
		c.SetUserContext(ctx)
		err := c.Next()
		metricsSkipped, _ = c.Locals(string(infracontext.MCPSkipMetricsKey)).(bool)
		return err
	})
	composer := mocks.NewComposer(t)
	roleScoper := mocks.NewRoleScoper(t)
	executor := pluginmocks.NewExecutor(t)
	limiter := ratelimitmocks.NewChecker(t)
	handler := mcphttp.NewHandler(
		mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(executor, discardLogger()), limiter),
		roleScoper,
	)
	app.Post(mcpPath, handler.Handle)

	body := `{"jsonrpc":"2.0","method":"unknown/method","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, raw := rpcRawCallWithHeaders(t, app, body, modernHeadersFor("unknown/method"))
	require.Equal(t, fiber.StatusAccepted, status)
	require.Empty(t, raw)
	require.True(t, metricsSkipped)
	require.Empty(t, requestTrace.Spans())
	require.Empty(t, roleScoper.Calls)
	require.Empty(t, limiter.Calls)
	require.Empty(t, executor.Calls)
	require.Empty(t, composer.Calls)
}

func TestHandler_ModernNotificationStillValidatesHeaders(t *testing.T) {
	t.Parallel()
	body := `{"jsonrpc":"2.0","method":"unknown/method","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, response := rpcCallWithHeaders(t, newAppWithoutConsumers(t), body, http.Header{
		"MCP-Protocol-Version": {"2026-07-28"},
	})
	require.Equal(t, fiber.StatusBadRequest, status)
	require.Equal(t, float64(-32020), response["error"].(map[string]any)["code"])
}

func TestHandler_LegacyNullIDIsNotification(t *testing.T) {
	t.Parallel()
	app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
	status, raw := rpcRawCallWithHeaders(
		t,
		app,
		`{"jsonrpc":"2.0","id":null,"method":"notifications/initialized"}`,
		nil,
	)
	require.Equal(t, fiber.StatusAccepted, status)
	require.Empty(t, raw)
}

func TestHandler_ModernServerDiscoverNotificationSkipsDownstreamEffects(t *testing.T) {
	t.Parallel()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(ids.New[ids.GatewayKind](), nil)
	requestTrace := trace.New("discover-notification", trace.Metadata{Kind: events.KindMCP})
	var metricsSkipped bool

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = trace.NewContext(ctx, requestTrace)
		c.SetUserContext(ctx)
		err := c.Next()
		metricsSkipped, _ = c.Locals(string(infracontext.MCPSkipMetricsKey)).(bool)
		return err
	})
	composer := mocks.NewComposer(t)
	roleScoper := mocks.NewRoleScoper(t)
	executor := pluginmocks.NewExecutor(t)
	limiter := ratelimitmocks.NewChecker(t)
	handler := mcphttp.NewHandler(
		mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(executor, discardLogger()), limiter),
		roleScoper,
	)
	app.Post(mcpPath, handler.Handle)

	body := `{"jsonrpc":"2.0","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, raw := rpcRawCallWithHeaders(t, app, body, modernHeadersFor("server/discover"))
	require.Equal(t, fiber.StatusAccepted, status)
	require.Empty(t, raw)
	require.True(t, metricsSkipped)
	require.Empty(t, requestTrace.Spans())
	require.Empty(t, roleScoper.Calls)
	require.Empty(t, limiter.Calls)
	require.Empty(t, executor.Calls)
	require.Empty(t, composer.Calls)
}

func TestHandler_ModernNullIDIsRequest(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{{Name: "search"}}, nil).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)
	body := `{"jsonrpc":"2.0","id":null,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, response := rpcCallWithHeaders(t, app, body, modernHeadersFor("tools/list"))
	require.Equal(t, fiber.StatusOK, status)
	require.Contains(t, response, "id")
	require.Nil(t, response["id"])
	require.Len(t, response["result"].(map[string]any)["tools"], 1)
}

func TestHandler_ModernInvalidIDsReturnInvalidRequest(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		id   string
	}{
		{name: "boolean", id: "true"},
		{name: "object", id: `{}`},
		{name: "array", id: `[]`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
			body := `{"jsonrpc":"2.0","id":` + tc.id + `,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
			status, response := rpcCallWithHeaders(t, app, body, modernHeadersFor("tools/list"))
			require.Equal(t, fiber.StatusBadRequest, status)
			require.Contains(t, response, "id")
			require.Nil(t, response["id"])
			require.Equal(t, float64(-32600), response["error"].(map[string]any)["code"])
		})
	}
}

func TestHandler_ModernUnsupportedMethodsReturn404(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"ping", "tools/subscribe"} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
			body := `{"jsonrpc":"2.0","id":8,"method":"` + method + `","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
			status, response := rpcCallWithHeaders(t, app, body, modernHeadersFor(method))
			require.Equal(t, fiber.StatusNotFound, status)
			require.Equal(t, float64(-32601), response["error"].(map[string]any)["code"])
		})
	}
}

func TestHandler_ModernMethodFilteringPrecedesConsumerLookup(t *testing.T) {
	t.Parallel()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(ids.New[ids.GatewayKind](), nil)
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandler(
		mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil),
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
	)
	app.Post(mcpPath, handler.Handle)
	body := `{"jsonrpc":"2.0","id":8,"method":"tools/subscribe","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, response := rpcCallWithHeaders(t, app, body, modernHeadersFor("tools/subscribe"))
	require.Equal(t, fiber.StatusNotFound, status)
	require.Equal(t, float64(-32601), response["error"].(map[string]any)["code"])
}

func TestHandler_ModernServerDiscoverUsesScopedLocalView(t *testing.T) {
	t.Parallel()
	authID := ids.New[ids.AuthKind]()
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	consumer := &consumerdomain.Consumer{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gatewayID,
		Name:        "virtual",
		Type:        consumerdomain.TypeMCP,
		Slug:        "virtual",
		Active:      true,
		AuthIDs:     []ids.AuthID{authID},
		RoutingMode: consumerdomain.RoutingModeRoleBased,
	}
	scopedConsumer := *consumer
	scopedConsumer.MCP = &consumerdomain.MCPPolicy{
		Toolkit: consumerdomain.Toolkit{{RegistryID: registryID, Tool: "search"}},
	}
	scoped := &appconsumer.RoutableConsumer{Consumer: &scopedConsumer}
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{{Consumer: consumer}})
	requestTrace := trace.New("discover", trace.Metadata{Kind: events.KindMCP})
	var metricsSkipped bool

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = trace.NewContext(ctx, requestTrace)
		c.SetUserContext(ctx)
		err := c.Next()
		metricsSkipped, _ = c.Locals(string(infracontext.MCPSkipMetricsKey)).(bool)
		return err
	})
	composer := mocks.NewComposer(t)
	roleScoper := mocks.NewRoleScoper(t)
	roleScoper.EXPECT().Scope(mock.Anything, mock.Anything, data).Return(scoped, nil).Once()
	executor := pluginmocks.NewExecutor(t)
	limiter := ratelimitmocks.NewChecker(t)
	handler := mcphttp.NewHandler(
		mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(executor, discardLogger()), limiter),
		roleScoper,
	)
	app.Post(mcpPath, handler.Handle)

	body := `{"jsonrpc":"2.0","id":21,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req := httptest.NewRequest(fiber.MethodPost, mcpPath, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "server/discover")
	req.Header.Set("Mcp-Session-Id", "ignored")
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	var response map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&response))

	require.Equal(t, fiber.StatusOK, res.StatusCode)
	require.Empty(t, res.Header.Get("Mcp-Session-Id"))
	result := response["result"].(map[string]any)
	require.Equal(t, []any{"2026-07-28", "2025-06-18", "2025-03-26", "2024-11-05"}, result["supportedVersions"])
	require.Equal(t, map[string]any{"tools": map[string]any{}}, result["capabilities"])
	require.Equal(t, "complete", result["resultType"])
	require.Equal(t, float64(300000), result["ttlMs"])
	require.Equal(t, "private", result["cacheScope"])
	require.Contains(t, result["_meta"].(map[string]any), "io.modelcontextprotocol/serverInfo")
	require.False(t, metricsSkipped)
	require.Empty(t, composer.Calls)
	require.Empty(t, executor.Calls)
	require.Empty(t, limiter.Calls)

	spans := requestTrace.Spans()
	require.Len(t, spans, 1)
	attrs, ok := spans[0].MCPAttrsCopy()
	require.True(t, ok)
	require.Equal(t, "server/discover", attrs.Method)
	require.Equal(t, "discovery", attrs.Operation)
	require.Zero(t, attrs.Targets)
	require.Zero(t, attrs.RPCErrorCode)
	require.Equal(t, fiber.StatusOK, attrs.UpstreamStatus)
	require.Empty(t, attrs.ServerName)
	require.Empty(t, attrs.RegistryID)
	require.False(t, spans[0].EndedAt().IsZero())
}

func TestHandler_ModernHappyPathUsesExistingDispatcher(t *testing.T) {
	t.Parallel()
	var tool appmcp.Tool
	require.NoError(t, json.Unmarshal([]byte(`{
		"name":"search",
		"inputSchema":{"type":"object","properties":{"query":{"type":"string","x-mcp-header":"X-Query"}}}
	}`), &tool))
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{tool}, nil).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)
	body := `{"jsonrpc":"2.0","id":"modern-1","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, response := rpcCallWithHeaders(t, app, body, modernHeadersFor("tools/list"))
	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, "modern-1", response["id"])
	result := response["result"].(map[string]any)
	require.Len(t, result["tools"], 1)
	require.Equal(t, "complete", result["resultType"])
	require.Equal(t, float64(300000), result["ttlMs"])
	require.Equal(t, "private", result["cacheScope"])
	serverInfo := result["_meta"].(map[string]any)["io.modelcontextprotocol/serverInfo"].(map[string]any)
	require.True(t, strings.HasPrefix(serverInfo["version"].(string), "1.0+"))
	require.False(t, containsHeaderAnnotation(result))
}

func TestHandler_ModernMethodsDispatchAndAdaptFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		body      string
		headers   http.Header
		setup     func(*mocks.Composer)
		resultKey string
		wantTTL   any
	}{
		{
			name:    "resource read",
			body:    `{"jsonrpc":"2.0","id":11,"method":"resources/read","params":{"uri":"file:///doc","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			headers: modernHeadersWithName("resources/read", "file:///doc"),
			setup: func(composer *mocks.Composer) {
				composer.EXPECT().ReadResource(mock.Anything, mock.Anything, "file:///doc").
					Return(json.RawMessage(`{"contents":[{"uri":"file:///doc","text":"kept"}],"extra":"preserved"}`), nil).Once()
			},
			resultKey: "contents",
			wantTTL:   float64(0),
		},
		{
			name:    "tool call",
			body:    `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"search","arguments":{"q":"value"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			headers: modernHeadersWithName("tools/call", "search"),
			setup: func(composer *mocks.Composer) {
				composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("search")).
					Return(json.RawMessage(`{"content":[{"type":"text","text":"kept"}],"extra":"preserved"}`), nil).Once()
			},
			resultKey: "content",
		},
		{
			name:    "prompts list",
			body:    `{"jsonrpc":"2.0","id":17,"method":"prompts/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			headers: modernHeadersFor("prompts/list"),
			setup: func(composer *mocks.Composer) {
				composer.EXPECT().ListPrompts(mock.Anything, mock.Anything).
					Return([]appmcp.Prompt{{Name: "writer"}}, nil).Once()
			},
			resultKey: "prompts",
			wantTTL:   float64(300000),
		},
		{
			name:    "prompt get",
			body:    `{"jsonrpc":"2.0","id":18,"method":"prompts/get","params":{"name":"writer","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			headers: modernHeadersWithName("prompts/get", "writer"),
			setup: func(composer *mocks.Composer) {
				composer.EXPECT().GetPrompt(mock.Anything, mock.Anything, "writer", mock.Anything).
					Return(json.RawMessage(`{"messages":[]}`), nil).Once()
			},
			resultKey: "messages",
		},
		{
			name:    "resources list",
			body:    `{"jsonrpc":"2.0","id":19,"method":"resources/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			headers: modernHeadersFor("resources/list"),
			setup: func(composer *mocks.Composer) {
				composer.EXPECT().ListResources(mock.Anything, mock.Anything).
					Return([]appmcp.Resource{{Name: "document", URI: "file:///doc"}}, nil).Once()
			},
			resultKey: "resources",
			wantTTL:   float64(300000),
		},
		{
			name:    "resource templates list",
			body:    `{"jsonrpc":"2.0","id":20,"method":"resources/templates/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
			headers: modernHeadersFor("resources/templates/list"),
			setup: func(composer *mocks.Composer) {
				composer.EXPECT().ListResourceTemplates(mock.Anything, mock.Anything).
					Return([]appmcp.ResourceTemplate{{Name: "document", URITemplate: "file:///{id}"}}, nil).Once()
			},
			resultKey: "resourceTemplates",
			wantTTL:   float64(300000),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			composer := mocks.NewComposer(t)
			tc.setup(composer)
			app := newApp(t, composer, consumerdomain.TypeMCP, true)
			status, response := rpcCallWithHeaders(t, app, tc.body, tc.headers)
			require.Equal(t, fiber.StatusOK, status)
			result := response["result"].(map[string]any)
			require.Contains(t, result, tc.resultKey)
			require.Equal(t, "complete", result["resultType"])
			require.Contains(t, result["_meta"].(map[string]any), "io.modelcontextprotocol/serverInfo")
			if tc.wantTTL != nil {
				require.Equal(t, tc.wantTTL, result["ttlMs"])
				require.Equal(t, "private", result["cacheScope"])
			} else {
				require.NotContains(t, result, "ttlMs")
				require.NotContains(t, result, "cacheScope")
			}
		})
	}
}

func TestHandler_ModernInvalidSuccessPayloadReturnsInternalError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result json.RawMessage
	}{
		{name: "nil", result: nil},
		{name: "empty raw", result: json.RawMessage{}},
		{name: "null", result: json.RawMessage(`null`)},
		{name: "array", result: json.RawMessage(`[]`)},
		{name: "non-object metadata", result: json.RawMessage(`{"_meta":[]}`)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			composer := mocks.NewComposer(t)
			composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("search")).
				Return(tc.result, nil).Once()
			app := newApp(t, composer, consumerdomain.TypeMCP, true)
			body := `{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"search","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
			status, response := rpcCallWithHeaders(t, app, body, modernHeadersWithName("tools/call", "search"))
			require.Equal(t, fiber.StatusInternalServerError, status)
			require.Equal(t, float64(-32603), response["error"].(map[string]any)["code"])
			require.Equal(t, float64(13), response["id"])
		})
	}
}

func TestHandler_ModernResourceMissUsesInvalidParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
	}{
		{name: "domain error", err: appmcp.ErrResourceNotFound},
		{name: "legacy upstream code", err: &appmcp.RPCError{Code: -32002, Message: "resource missing"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			composer := mocks.NewComposer(t)
			composer.EXPECT().ReadResource(mock.Anything, mock.Anything, "file:///missing").
				Return(nil, tc.err).Once()
			app := newApp(t, composer, consumerdomain.TypeMCP, true)
			body := `{"jsonrpc":"2.0","id":14,"method":"resources/read","params":{"uri":"file:///missing","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
			status, response := rpcCallWithHeaders(t, app, body, modernHeadersWithName("resources/read", "file:///missing"))
			require.Equal(t, fiber.StatusBadRequest, status)
			require.Equal(t, float64(-32602), response["error"].(map[string]any)["code"])
		})
	}
}

func TestHandler_LegacyResourceMissKeepsLegacyError(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ReadResource(mock.Anything, mock.Anything, "file:///missing").
		Return(nil, appmcp.ErrResourceNotFound).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)
	status, response := rpcCall(t, app, `{"jsonrpc":"2.0","id":16,"method":"resources/read","params":{"uri":"file:///missing"}}`)
	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, float64(-32002), response["error"].(map[string]any)["code"])
}

func TestHandler_ModernValidationPrecedesDownstream(t *testing.T) {
	authID := ids.New[ids.AuthKind]()
	gatewayID := ids.New[ids.GatewayKind]()
	consumer := &consumerdomain.Consumer{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gatewayID,
		Name:        "virtual",
		Type:        consumerdomain.TypeMCP,
		Slug:        "virtual",
		Active:      true,
		AuthIDs:     []ids.AuthID{authID},
		RoutingMode: consumerdomain.RoutingModeRoleBased,
	}
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{{Consumer: consumer}})
	requestTrace := trace.New("validation", trace.Metadata{Kind: events.KindMCP})
	var metricsSkipped bool

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = trace.NewContext(ctx, requestTrace)
		c.SetUserContext(ctx)
		err := c.Next()
		metricsSkipped, _ = c.Locals(string(infracontext.MCPSkipMetricsKey)).(bool)
		return err
	})

	composer := mocks.NewComposer(t)
	roleScoper := mocks.NewRoleScoper(t)
	executor := pluginmocks.NewExecutor(t)
	limiter := ratelimitmocks.NewChecker(t)
	handler := mcphttp.NewHandler(
		mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(executor, discardLogger()), limiter),
		roleScoper,
	)
	app.Post(mcpPath, handler.Handle)

	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, response := rpcCallWithHeaders(t, app, body, http.Header{
		"MCP-Protocol-Version": {"2026-07-28"},
		"Mcp-Method":           {"tools/call"},
		"Mcp-Name":             {"search"},
		"mCp-PaRaM-Unsafe":     {"blocked"},
	})

	require.Equal(t, fiber.StatusBadRequest, status)
	require.Equal(t, float64(-32020), response["error"].(map[string]any)["code"])
	require.True(t, metricsSkipped)
	require.Empty(t, requestTrace.Spans())
	roleScoper.AssertNotCalled(t, "Scope", mock.Anything, mock.Anything, mock.Anything)
	limiter.AssertNotCalled(t, "Check", mock.Anything, mock.Anything)
	executor.AssertNotCalled(t, "RunStage", mock.Anything, mock.Anything)
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandler_ModernValidationPrecedesConsumerLookup(t *testing.T) {
	t.Parallel()
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(ids.New[ids.GatewayKind](), nil)
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandler(
		mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil),
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
	)
	app.Post(mcpPath, handler.Handle)
	body := `{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	status, response := rpcCallWithHeaders(t, app, body, http.Header{
		"MCP-Protocol-Version": {"2026-07-28"},
		"Mcp-Method":           {"wrong"},
	})
	require.Equal(t, fiber.StatusBadRequest, status)
	require.Equal(t, float64(-32020), response["error"].(map[string]any)["code"])
}

func TestHandler_UnsupportedProtocolVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		header    string
		metadata  string
		requested string
	}{
		{name: "unknown header", header: "2099-01-01", requested: "2099-01-01"},
		{name: "unknown metadata", metadata: "2098-01-01", requested: "2098-01-01"},
		{name: "unknown header precedes modern metadata", header: "2099-01-01", metadata: "2026-07-28", requested: "2099-01-01"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := newApp(t, mocks.NewComposer(t), consumerdomain.TypeMCP, true)
			params := ""
			if tc.metadata != "" {
				params = `,"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + tc.metadata + `"}}`
			}
			headers := http.Header{}
			if tc.header != "" {
				headers.Set("MCP-Protocol-Version", tc.header)
			}
			status, body := rpcCallWithHeaders(t, app, `{"jsonrpc":"2.0","id":6,"method":"tools/list"`+params+`}`, headers)
			require.Equal(t, fiber.StatusBadRequest, status)
			rpcErr := body["error"].(map[string]any)
			require.Equal(t, float64(-32022), rpcErr["code"])
			require.Equal(t, tc.requested, rpcErr["data"].(map[string]any)["requested"])
			require.Equal(t, []any{"2026-07-28", "2025-06-18", "2025-03-26", "2024-11-05"}, rpcErr["data"].(map[string]any)["supported"])
		})
	}
}

func TestHandler_InvalidMetadataProtocolVersionFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
	}{
		{name: "empty", value: `""`},
		{name: "null", value: `null`},
		{name: "number", value: `1`},
		{name: "boolean", value: `true`},
		{name: "object", value: `{}`},
		{name: "array", value: `[]`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := newAppWithoutConsumers(t)
			body := `{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":` + tc.value + `}}}`
			status, response := rpcCall(t, app, body)
			require.Equal(t, fiber.StatusBadRequest, status)
			require.Equal(t, float64(-32602), response["error"].(map[string]any)["code"])
		})
	}
}

func TestHandler_LegacyHeaderPreservesLegacyDispatch(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()
	app := newApp(t, composer, consumerdomain.TypeMCP, true)
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}}`
	status, response := rpcCallWithHeaders(t, app, body, http.Header{
		"MCP-Protocol-Version": {"2025-06-18"},
		"Mcp-Method":           {"wrong"},
		"Mcp-Param-Unsafe":     {"ignored-for-legacy"},
	})
	require.Equal(t, fiber.StatusOK, status)
	require.NotNil(t, response["result"])
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

func TestHandler_ServerDiscover_ParsesMCPApps(t *testing.T) {
	tests := []struct {
		name, settings string
		status         int
		advertise      bool
		calls          int32
	}{
		{"supported", `{"mimeTypes":["text/html;profile=mcp-app"]}`, fiber.StatusOK, true, 1},
		{"unsupported", `{"mimeTypes":["text/html"]}`, fiber.StatusOK, false, 1},
		{"malformed", `{"mimeTypes":[7]}`, fiber.StatusBadRequest, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mediator := &recordingAppsMediator{}
			app := newAppWithRegistries(t, mediator, modernMCPRegistry(t, ids.New[ids.GatewayKind]()))
			request := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{` +
				`"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":` +
				`{"extensions":{"io.modelcontextprotocol/ui":` + tt.settings + `}}}}}`
			status, body := rpcCallWithHeaders(t, app, request, modernHeadersFor("server/discover"))
			require.Equal(t, tt.status, status)
			require.Equal(t, tt.calls, mediator.calls.Load())
			if status == fiber.StatusBadRequest {
				require.Equal(t, float64(-32602), body["error"].(map[string]any)["code"])
				return
			}
			capabilities := body["result"].(map[string]any)["capabilities"].(map[string]any)
			for _, kind := range []string{"tools", "prompts", "resources"} {
				require.Contains(t, capabilities, kind)
			}
			if !tt.advertise {
				require.NotContains(t, capabilities, "extensions")
				return
			}
			require.Equal(t, map[string]any{appmcp.MCPAppsExtensionIdentifier: map[string]any{
				"mimeTypes": []any{appmcp.MCPAppsHTMLMIMEType},
			}}, capabilities["extensions"])
		})
	}
}
