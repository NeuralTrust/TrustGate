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
	"net/http"
	"net/http/httptest"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type whoAmIGateway struct{ gw *gatewaydomain.Gateway }

func (r whoAmIGateway) Resolve(*fiber.Ctx) (*gatewaydomain.Gateway, error) { return r.gw, nil }

type whoAmIConsumers struct {
	consumers []appconsumer.KeyConsumer
	err       error
	gotKey    string
}

func (s *whoAmIConsumers) ForAPIKey(
	_ context.Context, _ ids.GatewayID, rawKey string,
) ([]appconsumer.KeyConsumer, error) {
	s.gotKey = rawKey
	return s.consumers, s.err
}

func whoAmIApp(service appconsumer.APIKeyConsumers, gateway *gatewaydomain.Gateway) *fiber.App {
	handler := mcphttp.NewWhoAmIHandler(whoAmIGateway{gw: gateway}, service, "acme.neuraltrust.ai")
	app := fiber.New()
	app.Get(mcphttp.WhoAmIPath, handler.Handle)
	return app
}

// The plane is reached over TLS on its own host, and both are what the MCP
// URL in the answer is built from.
func whoAmIRequest(key string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, mcphttp.WhoAmIPath, nil)
	request.Host = "gw.mcp.neuraltrust.ai"
	request.Header.Set("X-Forwarded-Proto", "https")
	if key != "" {
		request.Header.Set("X-AG-API-Key", key)
	}
	return request
}

func callWhoAmI(t *testing.T, app *fiber.App, key string) (int, mcphttp.WhoAmIResponse) {
	t.Helper()
	request := whoAmIRequest(key)
	response, err := app.Test(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	var body mcphttp.WhoAmIResponse
	_ = json.NewDecoder(response.Body).Decode(&body)
	return response.StatusCode, body
}

// The point of the endpoint: a client arrives holding one secret and leaves
// knowing every address it can use. The LLM consumer is the reason it returns
// URLs rather than slugs — it lives on the proxy plane, a host this plane
// never appears on, so no client could compose it from what it had.
func TestWhoAmI_NamesBothPlanesWithTheirAddresses(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{consumers: []appconsumer.KeyConsumer{
		{Slug: "support-agent", Name: "Support Agent", Type: consumerdomain.TypeMCP, Active: true},
		{Slug: "support-llm", Name: "Support Models", Type: consumerdomain.TypeLLM, Active: true},
	}}
	app := whoAmIApp(service, &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"})

	status, body := callWhoAmI(t, app, "ag_secret")

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, "acme", body.Gateway)
	require.Len(t, body.Consumers, 2)
	require.Equal(t, "https://gw.mcp.neuraltrust.ai/support-agent/mcp", body.Consumers[0].URL)
	require.Equal(t, "https://acme.acme.neuraltrust.ai/support-llm/v1", body.Consumers[1].URL)
	require.Equal(t, "ag_secret", service.gotKey)
}

// A gateway published on a domain of its own is reached there, not at the
// suffix the others share.
func TestWhoAmI_PrefersTheGatewaysOwnDomainForTheLLMPlane(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{consumers: []appconsumer.KeyConsumer{
		{Slug: "support-llm", Type: consumerdomain.TypeLLM, Active: true},
	}}
	app := whoAmIApp(service, &gatewaydomain.Gateway{
		ID: ids.New[ids.GatewayKind](), Slug: "acme", Domain: "ai.acme.com",
	})

	_, body := callWhoAmI(t, app, "ag_secret")

	require.Equal(t, "https://ai.acme.com/support-llm/v1", body.Consumers[0].URL)
}

// The actor decides which handle a client gets, so it travels with the
// consumer rather than being discovered later.
func TestWhoAmI_SaysWhichActorEachConsumerIs(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{consumers: []appconsumer.KeyConsumer{
		{Slug: "batch", Type: consumerdomain.TypeMCP, Active: true},
		{
			Slug: "assistant", Type: consumerdomain.TypeMCP, Active: true,
			ActsForUsers: true, IdentitySource: "app",
		},
	}}
	app := whoAmIApp(service, &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"})

	_, body := callWhoAmI(t, app, "ag_secret")

	require.False(t, body.Consumers[0].ActsForUsers)
	require.True(t, body.Consumers[1].ActsForUsers)
	require.Equal(t, "app", body.Consumers[1].IdentitySource)
}

// One refusal, whatever is wrong with the key: the endpoint takes no slug, so
// a talkative answer here would enumerate a gateway's consumers to anyone.
func TestWhoAmI_RefusesAKeyItDoesNotKnow(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{err: appconsumer.ErrAPIKeyUnknown}
	app := whoAmIApp(service, &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"})

	status, body := callWhoAmI(t, app, "ag_nope")

	require.Equal(t, fiber.StatusUnauthorized, status)
	require.Empty(t, body.Consumers)
}

// A key that reaches nothing verified, so it gets an answer — an empty one,
// which is what tells its holder to go and ask an admin.
func TestWhoAmI_AnswersEmptyForAKeyBoundToNoConsumer(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{consumers: nil}
	app := whoAmIApp(service, &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"})

	status, body := callWhoAmI(t, app, "ag_secret")

	require.Equal(t, fiber.StatusOK, status)
	require.NotNil(t, body.Consumers)
	require.Empty(t, body.Consumers)
}

// Nothing in the answer is the gateway's own business: no ids, no upstream
// addresses, no credential.
func TestWhoAmI_CarriesNoInternalIdentifiers(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{consumers: []appconsumer.KeyConsumer{
		{Slug: "support-agent", Name: "Support Agent", Type: consumerdomain.TypeMCP, Active: true},
	}}
	gateway := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	app := whoAmIApp(service, gateway)

	response, err := app.Test(whoAmIRequest("ag_secret"))
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()

	raw := make([]byte, 4096)
	n, _ := response.Body.Read(raw)
	payload := string(raw[:n])
	require.NotContains(t, payload, gateway.ID.String())
	require.NotContains(t, payload, "ag_secret")
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
}
