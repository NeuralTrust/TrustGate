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

package a2a_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	a2ahttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/a2a"
	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type httpUpstream struct{}

func (httpUpstream) Post(ctx context.Context, url string, header http.Header, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = header
	return http.DefaultClient.Do(req)
}

type allowAll struct{}

func (allowAll) RunStage(context.Context, appplugins.StageInput) (*appplugins.StageOutcome, error) {
	return &appplugins.StageOutcome{}, nil
}

const card10 = `{"name":"Travel planner","capabilities":{"streaming":true},"skills":[],` +
	`"supportedInterfaces":[{"url":"https://agent.example/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`

func newApp(t *testing.T, agentURL string) (*fiber.App, *registrydomain.Registry) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	reg := &registrydomain.Registry{
		ID:      ids.New[ids.RegistryKind](),
		Name:    "Travel planner",
		Type:    registrydomain.TypeA2A,
		Enabled: true,
		A2ATarget: &registrydomain.A2ATarget{
			Provider:        registrydomain.A2AProviderGeneric,
			ProtocolVersion: registrydomain.A2AVersion10,
			URL:             agentURL,
			Card:            []byte(card10),
			Auth:            &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeNone},
		},
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: ids.New[ids.GatewayKind](),
			Slug:      "research-bot",
			Type:      consumerdomain.TypeA2A,
		},
		Registries: []*registrydomain.Registry{reg},
	}
	forwarder := appa2a.NewForwarder(httpUpstream{}, appa2a.NewPluginRunner(allowAll{}, logger), appa2a.NewCredentials(), logger)
	h := a2ahttp.NewHandler(forwarder)
	app := fiber.New()
	withConsumer := func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithConsumer(c.UserContext(), rc))
		return c.Next()
	}
	app.Get(router.AgentCardPath, withConsumer, h.Card)
	app.Post(router.AgentRPCPath, withConsumer, h.RPC)
	return app, reg
}

func do(t *testing.T, app *fiber.App, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp.StatusCode, body
}

func TestCardServesThePinnedCardOnTheGateway(t *testing.T) {
	app, reg := newApp(t, "https://agent.example/a2a")
	req := httptest.NewRequest(http.MethodGet, "/research-bot/agents/Travel%20planner/.well-known/agent-card.json", nil)
	req.Host = "agents.example.com"
	status, body := do(t, app, req)
	require.Equal(t, http.StatusOK, status)
	var card struct {
		SupportedInterfaces []struct {
			URL string `json:"url"`
		} `json:"supportedInterfaces"`
	}
	require.NoError(t, json.Unmarshal(body, &card))
	require.Len(t, card.SupportedInterfaces, 1)
	assert.Equal(t, "http://agents.example.com/research-bot/agents/"+reg.ID.String(), card.SupportedInterfaces[0].URL)

	status, _ = do(t, app, httptest.NewRequest(http.MethodGet, "/research-bot/agents/unknown/.well-known/agent-card.json", nil))
	assert.Equal(t, http.StatusNotFound, status)
}

func TestRPCAnswersWithTheCallersID(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"agent-id","result":{"message":{"messageId":"m","role":"ROLE_AGENT","parts":[{"text":"hi"}]}}}`))
	}))
	t.Cleanup(agent.Close)
	app, reg := newApp(t, agent.URL)

	req := httptest.NewRequest(http.MethodPost, "/research-bot/agents/"+reg.ID.String(),
		strings.NewReader(`{"jsonrpc":"2.0","id":"caller-id","method":"SendMessage","params":{"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"hello"}]}}}`))
	req.Header.Set("Content-Type", "application/json")
	status, body := do(t, app, req)
	require.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":"caller-id","result":{"message":{"messageId":"m","role":"ROLE_AGENT","parts":[{"text":"hi"}]}}}`, string(body))
}

func TestRPCRefusals(t *testing.T) {
	app, reg := newApp(t, "https://agent.example/a2a")
	path := "/research-bot/agents/" + reg.ID.String()
	cases := []struct {
		name        string
		contentType string
		body        string
		want        string
	}{
		{name: "not JSON content", contentType: "text/plain", body: `{}`, want: `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}`},
		{name: "not JSON", contentType: "application/json", body: `{`, want: `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid JSON payload"}}`},
		{name: "batch", contentType: "application/json", body: `[]`, want: `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}`},
		{name: "0.3 method", contentType: "application/json", body: `{"jsonrpc":"2.0","id":3,"method":"message/send","params":{}}`, want: `{"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found"}}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.contentType)
		status, body := do(t, app, req)
		assert.Equal(t, http.StatusOK, status, tc.name)
		assert.JSONEq(t, tc.want, string(body), tc.name)
	}

	status, _ := do(t, app, httptest.NewRequest(http.MethodPost, "/research-bot/agents/unknown", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusNotFound, status)
}
