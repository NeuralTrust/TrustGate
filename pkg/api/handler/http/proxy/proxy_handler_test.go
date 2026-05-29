package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	proxyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/proxy"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/AgentGateway/pkg/app/proxy/mocks"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func newTestApp(t *testing.T) (*fiber.App, *proxymocks.Forwarder) {
	t.Helper()
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	handler := proxyhttp.NewProxyHandler(fwd)
	app.All("/v1/*", handler.Handle)
	return app, fwd
}

func newProxyRequest(gatewayID, backendID string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt"}`))
	req.Header.Set("Content-Type", "application/json")
	if gatewayID != "" {
		req.Header.Set(proxyhttp.HeaderGatewayID, gatewayID)
	}
	if backendID != "" {
		req.Header.Set(proxyhttp.HeaderBackendID, backendID)
	}
	return req
}

func decodeError(t *testing.T, body io.Reader) helpers.ErrorBody {
	t.Helper()
	var eb helpers.ErrorBody
	if err := json.NewDecoder(body).Decode(&eb); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return eb
}

func TestHandle_MissingRoutingHeaders(t *testing.T) {
	app, _ := newTestApp(t)

	resp, err := app.Test(newProxyRequest("", ""))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "invalid_routing" {
		t.Fatalf("error = %q, want invalid_routing", eb.Error)
	}
}

func TestHandle_InvalidGatewayHeader(t *testing.T) {
	app, _ := newTestApp(t)

	resp, err := app.Test(newProxyRequest("not-a-uuid", uuid.NewString()))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHandle_Success_RelaysResponse(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.MatchedBy(func(in appproxy.ForwardInput) bool {
			return in.Request != nil && in.Request.Method == http.MethodPost
		})).
		Return(&appproxy.ForwardResult{
			StatusCode: 200,
			Headers: map[string][]string{
				"Content-Type":      {"application/json"},
				"X-Upstream":        {"openai"},
				"Transfer-Encoding": {"chunked"},
			},
			Body: []byte(`{"ok":true}`),
		}, nil).
		Once()

	resp, err := app.Test(newProxyRequest(uuid.NewString(), uuid.NewString()))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Upstream"); got != "openai" {
		t.Fatalf("X-Upstream = %q, want openai", got)
	}
	if got := resp.Header.Get("Transfer-Encoding"); got == "chunked" {
		t.Fatal("hop-by-hop Transfer-Encoding header should not be relayed")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", string(body))
	}
}

func TestHandle_ProviderNotImplemented(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrProviderNotImplemented).
		Once()

	resp, err := app.Test(newProxyRequest(uuid.NewString(), uuid.NewString()))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "not_implemented" {
		t.Fatalf("error = %q, want not_implemented", eb.Error)
	}
}

func TestHandle_NoTargetAvailable(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrNoTargetAvailable).
		Once()

	resp, err := app.Test(newProxyRequest(uuid.NewString(), uuid.NewString()))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}
