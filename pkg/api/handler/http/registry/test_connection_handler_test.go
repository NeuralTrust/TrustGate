package registry_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registryhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry"
	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	regmocks "github.com/NeuralTrust/AgentGateway/pkg/app/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestConnectionApp(h *registryhttp.TestConnectionHandler) *fiber.App {
	app := fiber.New()
	app.Post("/v1/gateways/:gateway_id/registries/test-connection", h.Handle)
	return app
}

func TestTestConnectionHandler_Inline_OK(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	svc := regmocks.NewConnectionTester(t)
	svc.EXPECT().
		Test(mock.Anything, mock.MatchedBy(func(in appregistry.TestConnectionInput) bool {
			return in.GatewayID == gwID && in.RegistryID == nil && in.Provider == "openai"
		})).
		Return(appregistry.TestConnectionResult{OK: true, Stage: "authentication", Provider: "openai", StatusCode: 200, LatencyMs: 12}, nil).
		Once()

	app := newTestConnectionApp(registryhttp.NewTestConnectionHandler(svc))
	body := `{"provider":"openai","auth":{"type":"api_key","api_key":{"api_key":"sk-1"}}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gateways/"+gwID.String()+"/registries/test-connection", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got map[string]any
	raw, _ := io.ReadAll(resp.Body)
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, true, got["ok"])
	assert.Equal(t, "authentication", got["stage"])
	assert.Equal(t, "openai", got["provider"])
}

func TestTestConnectionHandler_InvalidBody(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	svc := regmocks.NewConnectionTester(t)

	app := newTestConnectionApp(registryhttp.NewTestConnectionHandler(svc))
	req := httptest.NewRequest(http.MethodPost, "/v1/gateways/"+gwID.String()+"/registries/test-connection", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestTestConnectionHandler_InvalidGatewayID(t *testing.T) {
	svc := regmocks.NewConnectionTester(t)
	app := newTestConnectionApp(registryhttp.NewTestConnectionHandler(svc))
	req := httptest.NewRequest(http.MethodPost, "/v1/gateways/not-a-uuid/registries/test-connection", strings.NewReader(`{"provider":"openai","auth":{"type":"api_key","api_key":{"api_key":"x"}}}`))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
