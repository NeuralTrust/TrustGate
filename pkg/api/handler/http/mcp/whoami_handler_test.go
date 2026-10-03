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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
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
	key       appconsumer.KeyInfo
	err       error
	gotKey    string
}

func (s *whoAmIConsumers) ForAPIKey(
	_ context.Context, _ ids.GatewayID, rawKey string,
) (*appconsumer.KeyDescription, error) {
	s.gotKey = rawKey
	if s.err != nil {
		return nil, s.err
	}
	return &appconsumer.KeyDescription{Key: s.key, Consumers: s.consumers}, nil
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

// A key that retires itself is the failure a client discovers as a 401 in
// production, months after whoever issued it left. So the key says when.
func TestWhoAmI_SaysWhenTheKeyRetiresItself(t *testing.T) {
	t.Parallel()
	expiry := time.Date(2027, 3, 1, 9, 30, 0, 0, time.UTC)
	service := &whoAmIConsumers{
		key:       appconsumer.KeyInfo{Name: "prod", ExpiresAt: &expiry},
		consumers: []appconsumer.KeyConsumer{{Slug: "assistant", Type: consumerdomain.TypeMCP, Active: true}},
	}
	app := whoAmIApp(service, &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"})

	_, body := callWhoAmI(t, app, "ag_secret")

	require.Equal(t, "prod", body.Key.Name)
	require.Equal(t, "2027-03-01T09:30:00Z", body.Key.ExpiresAt)
}

// A key that never expires says nothing rather than a far-off date a client
// would have to recognise as "never".
func TestWhoAmI_LeavesTheExpiryOutWhenThereIsNone(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{
		key:       appconsumer.KeyInfo{Name: "prod"},
		consumers: []appconsumer.KeyConsumer{{Slug: "assistant", Type: consumerdomain.TypeMCP, Active: true}},
	}
	app := whoAmIApp(service, &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"})

	_, body := callWhoAmI(t, app, "ag_secret")

	require.Empty(t, body.Key.ExpiresAt)
}

// The first tool call against an unconnected server fails with a refusal the
// caller can do nothing about. Answering it here, before the call, is the
// difference between a client that can tell its operator what to do and one
// that only knows something went wrong.
func TestWhoAmI_NamesWhatIsStillWaitingToBeConnected(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{consumers: []appconsumer.KeyConsumer{{
		Slug: "assistant", Type: consumerdomain.TypeMCP, Active: true,
		Upstreams: []appconsumer.KeyUpstream{
			{
				Server: "Confluence", Provider: "atlassian",
				Account: appconsumer.KeyUpstreamShared, Connected: true,
			},
			{
				Server: "Notion", Provider: "notion",
				Account: appconsumer.KeyUpstreamShared,
				Blocked: appconsumer.KeyBlockedAdministrator,
			},
			{
				Server: "GitHub", Provider: "github",
				Account: appconsumer.KeyUpstreamUser,
				Blocked: appconsumer.KeyBlockedEndUser,
			},
		},
	}}}
	app := whoAmIApp(service, &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"})

	_, body := callWhoAmI(t, app, "ag_secret")

	upstreams := body.Consumers[0].Upstreams
	require.Len(t, upstreams, 3)
	require.Equal(t, "Confluence", upstreams[0].Server)
	require.True(t, upstreams[0].Connected)
	require.Empty(t, upstreams[0].Blocked, "a connected shared account is ready and says nothing")
	require.Equal(t, "shared", upstreams[1].Account)
	require.Equal(t, "administrator", upstreams[1].Blocked, "nobody calling can connect an account they do not own")
	require.Equal(t, "user", upstreams[2].Account)
	require.Equal(t, "end_user", upstreams[2].Blocked, "the application names the person it acts for")
}

// A consumer whose servers all carry their own credential is not "everything
// connected" and not "nothing to connect" — there is no list, and the field is
// absent rather than an empty array a client would have to interpret.
func TestWhoAmI_SaysNothingAboutUpstreamsThatNeedNoAccount(t *testing.T) {
	t.Parallel()
	service := &whoAmIConsumers{consumers: []appconsumer.KeyConsumer{
		{Slug: "assistant", Type: consumerdomain.TypeMCP, Active: true},
	}}
	app := whoAmIApp(service, &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"})

	_, body := callWhoAmI(t, app, "ag_secret")

	require.Nil(t, body.Consumers[0].Upstreams)
}

// --- The fixed entry point: a host that names no gateway ---

type noGateway struct{}

func (noGateway) Resolve(*fiber.Ctx) (*gatewaydomain.Gateway, error) {
	return nil, errors.New("host names no gateway")
}

type keyStore map[string]*authdomain.Auth

func (k keyStore) FindByAPIKey(_ context.Context, rawKey string) (*authdomain.Auth, error) {
	if a, ok := k[rawKey]; ok {
		return a, nil
	}
	return nil, authdomain.ErrNotFound
}

type gatewaysByID map[ids.GatewayID]*gatewaydomain.Gateway

func (g gatewaysByID) FindByID(_ context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	if gw, ok := g[id]; ok {
		return gw, nil
	}
	return nil, errors.New("not found")
}

type countingLimiter struct {
	calls   int
	subject string
	err     error
}

func (l *countingLimiter) Check(_ context.Context, _ appoauth.ConnectAttemptScope, subject string) error {
	l.calls++
	l.subject = subject
	return l.err
}

func fixedHostApp(service appconsumer.APIKeyConsumers, keys keyStore, gateways gatewaysByID, limiter *countingLimiter) *fiber.App {
	handler := mcphttp.NewWhoAmIHandler(noGateway{}, service, "acme.neuraltrust.ai",
		mcphttp.WithWhoAmIGatewayFromKey(keys, gateways, "mcp.neuraltrust.ai", limiter, func(string, string) string { return "203.0.113.7" }),
	)
	app := fiber.New()
	app.Get(mcphttp.WhoAmIPath, handler.Handle)
	return app
}

func callFixedHost(t *testing.T, app *fiber.App, key string) (int, mcphttp.WhoAmIResponse, http.Header) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, mcphttp.WhoAmIPath, nil)
	request.Host = "agentgateway-mcp.neuraltrust.ai"
	request.Header.Set("X-Forwarded-Proto", "https")
	if key != "" {
		request.Header.Set("X-AG-API-Key", key)
	}
	response, err := app.Test(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	var body mcphttp.WhoAmIResponse
	_ = json.NewDecoder(response.Body).Decode(&body)
	return response.StatusCode, body, response.Header
}

// A client can start from its key alone: on a host that names no gateway the
// key says which one it belongs to, and the answer addresses that gateway's own
// planes — never the fixed host, which serves nothing but this.
func TestWhoAmI_FindsTheGatewayFromTheKeyOnAFixedHost(t *testing.T) {
	t.Parallel()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	service := &whoAmIConsumers{consumers: []appconsumer.KeyConsumer{
		{Slug: "support-agent", Type: consumerdomain.TypeMCP, Active: true},
		{Slug: "support-llm", Type: consumerdomain.TypeLLM, Active: true},
	}}
	limiter := &countingLimiter{}
	app := fixedHostApp(service, keyStore{"ag_secret": {GatewayID: gw.ID}}, gatewaysByID{gw.ID: gw}, limiter)

	status, body, _ := callFixedHost(t, app, "ag_secret")

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, "acme", body.Gateway)
	require.Equal(t, "https://acme.mcp.neuraltrust.ai/support-agent/mcp", body.Consumers[0].URL)
	require.Equal(t, "https://acme.acme.neuraltrust.ai/support-llm/v1", body.Consumers[1].URL)
	require.Equal(t, 1, limiter.calls)
	require.Equal(t, "203.0.113.7", limiter.subject)
}

func TestWhoAmI_RefusesAnUnknownKeyOnTheFixedHost(t *testing.T) {
	t.Parallel()
	limiter := &countingLimiter{}
	app := fixedHostApp(&whoAmIConsumers{}, keyStore{}, gatewaysByID{}, limiter)

	status, _, _ := callFixedHost(t, app, "ag_nobody")
	require.Equal(t, fiber.StatusUnauthorized, status)

	status, _, _ = callFixedHost(t, app, "")
	require.Equal(t, fiber.StatusUnauthorized, status)
	require.Equal(t, 2, limiter.calls, "every lookup is counted, a failed one included")
}

// An unknown key is never cached, so each guess reaches the key store: the
// fixed host counts them per source and stops answering past the limit.
func TestWhoAmI_RateLimitsKeyLookupsOnTheFixedHost(t *testing.T) {
	t.Parallel()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	limiter := &countingLimiter{err: &appoauth.ConnectRateLimitExceeded{RetryAfter: 1500 * time.Millisecond}}
	app := fixedHostApp(&whoAmIConsumers{}, keyStore{"ag_secret": {GatewayID: gw.ID}}, gatewaysByID{gw.ID: gw}, limiter)

	status, _, header := callFixedHost(t, app, "ag_secret")

	require.Equal(t, fiber.StatusTooManyRequests, status)
	require.Equal(t, "2", header.Get("Retry-After"))
}

// A host that does name the gateway never takes the key path: nothing is
// looked up by key and nothing is counted.
func TestWhoAmI_KeepsTheHostsGatewayWhenItNamesOne(t *testing.T) {
	t.Parallel()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	limiter := &countingLimiter{}
	handler := mcphttp.NewWhoAmIHandler(whoAmIGateway{gw: gw},
		&whoAmIConsumers{consumers: []appconsumer.KeyConsumer{{Slug: "support-agent", Type: consumerdomain.TypeMCP, Active: true}}},
		"acme.neuraltrust.ai",
		mcphttp.WithWhoAmIGatewayFromKey(keyStore{}, gatewaysByID{}, "mcp.neuraltrust.ai", limiter, nil),
	)
	app := fiber.New()
	app.Get(mcphttp.WhoAmIPath, handler.Handle)

	status, body := callWhoAmI(t, app, "ag_secret")

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, "https://gw.mcp.neuraltrust.ai/support-agent/mcp", body.Consumers[0].URL)
	require.Zero(t, limiter.calls)
}

// A Hybrid gateway is served only by its own data plane. The cloud still holds
// its keys, so without this it would answer with its own URLs and every call
// made on them would be refused: it points the key home instead, in the words
// the proxy uses for that gateway's traffic.
func hybridGateway() *gatewaydomain.Gateway {
	return &gatewaydomain.Gateway{
		ID:           ids.New[ids.GatewayKind](),
		Slug:         "acme",
		Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHybrid},
	}
}

func callWhoAmIRaw(t *testing.T, app *fiber.App, request *http.Request) (int, httpio.ErrorBody) {
	t.Helper()
	response, err := app.Test(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	var body httpio.ErrorBody
	_ = json.NewDecoder(response.Body).Decode(&body)
	return response.StatusCode, body
}

func TestWhoAmI_PointsAHybridKeyAtItsOwnDataPlane(t *testing.T) {
	t.Parallel()
	gw := hybridGateway()
	service := &whoAmIConsumers{consumers: []appconsumer.KeyConsumer{{Slug: "support-agent", Type: consumerdomain.TypeMCP, Active: true}}}
	handler := mcphttp.NewWhoAmIHandler(noGateway{}, service, "acme.neuraltrust.ai",
		mcphttp.WithWhoAmIGatewayFromKey(keyStore{"ag_secret": {GatewayID: gw.ID}}, gatewaysByID{gw.ID: gw},
			"mcp.neuraltrust.ai", &countingLimiter{}, func(string, string) string { return "203.0.113.7" }),
		mcphttp.WithWhoAmIRefuseHybrid(),
	)
	app := fiber.New()
	app.Get(mcphttp.WhoAmIPath, handler.Handle)

	request := httptest.NewRequest(http.MethodGet, mcphttp.WhoAmIPath, nil)
	request.Host = "agentgateway-mcp.neuraltrust.ai"
	request.Header.Set("X-AG-API-Key", "ag_secret")
	status, body := callWhoAmIRaw(t, app, request)

	require.Equal(t, fiber.StatusMisdirectedRequest, status)
	require.Equal(t, middleware.ErrCodeHybridGateway, body.Error)
}

// Only a key that holds is told: a wrong one learns nothing about the gateway.
func TestWhoAmI_TellsNoOneWithoutAKeyThatAGatewayIsHybrid(t *testing.T) {
	t.Parallel()
	handler := mcphttp.NewWhoAmIHandler(whoAmIGateway{gw: hybridGateway()},
		&whoAmIConsumers{err: appconsumer.ErrAPIKeyUnknown}, "acme.neuraltrust.ai",
		mcphttp.WithWhoAmIRefuseHybrid(),
	)
	app := fiber.New()
	app.Get(mcphttp.WhoAmIPath, handler.Handle)

	status, _ := callWhoAmIRaw(t, app, whoAmIRequest("ag_guess"))

	require.Equal(t, fiber.StatusUnauthorized, status)
}

// The Hybrid data plane itself serves the gateway, so it answers as usual.
func TestWhoAmI_AnswersAHybridKeyOnItsOwnDataPlane(t *testing.T) {
	t.Parallel()
	app := whoAmIApp(&whoAmIConsumers{consumers: []appconsumer.KeyConsumer{
		{Slug: "support-agent", Type: consumerdomain.TypeMCP, Active: true},
	}}, hybridGateway())

	status, body := callWhoAmI(t, app, "ag_secret")

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, "https://gw.mcp.neuraltrust.ai/support-agent/mcp", body.Consumers[0].URL)
}
