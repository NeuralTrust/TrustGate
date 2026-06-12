package mcp_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	"github.com/NeuralTrust/AgentGateway/pkg/app/mcp/mocks"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
)

const mcpPath = "/virtual/mcp"

func newApp(t *testing.T, composer appmcp.Composer, consumerType consumerdomain.Type, authorized bool) *fiber.App {
	t.Helper()
	authID := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "virtual",
		Type:      consumerType,
		Path:      mcpPath,
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
	handler := mcphttp.NewHandler(appmcp.NewRPCGateway(composer))
	app.Post(mcpPath, handler.Handle)
	app.Get(mcpPath, handler.MethodNotAllowed)
	return app
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
