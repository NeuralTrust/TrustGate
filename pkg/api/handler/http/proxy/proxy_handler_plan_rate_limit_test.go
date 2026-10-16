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

package proxy_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proxyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/proxy"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// planBurstPlugin is the policy that answers before the upstream. It stands in
// for TrustGuard evaluate, which returns the plan limiter's flat 429.
type planBurstPlugin struct {
	err error
}

func (planBurstPlugin) Name() string { return "trustguard" }
func (planBurstPlugin) MandatoryStages() []policydomain.Stage {
	return []policydomain.Stage{policydomain.StagePreRequest}
}
func (planBurstPlugin) SupportedStages() []policydomain.Stage {
	return []policydomain.Stage{policydomain.StagePreRequest}
}
func (planBurstPlugin) SupportedModes() []policydomain.Mode {
	return []policydomain.Mode{policydomain.ModeEnforce}
}
func (planBurstPlugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}
func (planBurstPlugin) ValidateConfig(map[string]any) error { return nil }
func (planBurstPlugin) MutatesRequestBody() bool            { return false }
func (planBurstPlugin) MutatesResponseBody() bool           { return false }
func (planBurstPlugin) MutatesMetadata() bool               { return false }
func (p planBurstPlugin) Execute(context.Context, appplugins.ExecInput) (*appplugins.Result, error) {
	return nil, p.err
}

func authStubRoutable(gatewayID ids.GatewayID, authID ids.AuthID, rc appconsumer.RoutableConsumer) fiber.Handler {
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{rc})
	return func(c *fiber.Ctx) error {
		authCtx := &appauth.AuthContext{Method: appauth.MethodAPIKey, GatewayID: gatewayID, AuthID: authID}
		ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
		ctx = appconsumer.WithGatewayID(ctx, gatewayID)
		ctx = appconsumer.WithAuthID(ctx, authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func planBurstConsumer(gatewayID ids.GatewayID, authID ids.AuthID, policies []*policydomain.Policy) appconsumer.RoutableConsumer {
	return appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gatewayID,
			Slug:      consumerSlug,
			Active:    true,
			Type:      domainconsumer.TypeLLM,
			AuthIDs:   []ids.AuthID{authID},
			LBConfig:  &domainconsumer.LBConfig{Algorithm: loadbalancer.AlgorithmRoundRobin},
		},
		Registries: []*registrydomain.Registry{{
			ID:        ids.New[ids.RegistryKind](),
			GatewayID: gatewayID,
			Name:      "openai",
			Type:      registrydomain.TypeLLM,
			LLMTarget: &registrydomain.LLMTarget{
				Provider: "openai",
				Auth:     registrydomain.NewAPIKeyAuth("sk-1"),
			},
		}},
		Policies: policies,
	}
}

func forwarderWithPolicies(t *testing.T, plugin appplugins.Plugin, limiter ratelimitapp.Checker) appproxy.Forwarder {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(plugin))
	cacheClient := cachemocks.NewClient(t)
	cacheClient.EXPECT().Set(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	cacheClient.EXPECT().Get(mock.Anything, mock.Anything).Return("", errors.New("miss")).Maybe()
	cacheClient.EXPECT().RedisClient().Return(nil).Maybe()
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil),
		cacheClient,
		cache.NewTTLMapManager(time.Minute),
		proxymocks.NewProviderInvoker(t),
		appplugins.NewExecutor(reg, slog.New(slog.DiscardHandler)),
		nil,
		approuting.NewResolver(),
		nil,
		limiter,
		nil,
		slog.New(slog.DiscardHandler),
	)
}

func postChat(t *testing.T, app *fiber.App) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, proxyPath, strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	return resp
}

// TestHandle_PlanBurstRateLimitUsesDialectEnvelope is the HTTP path a client
// hits: an application with policies, a plan burst of limit 100, and the flat
// body a guard copies from the plan limiter. The response is the OpenAI
// envelope, and Retry-After stays.
func TestHandle_PlanBurstRateLimitUsesDialectEnvelope(t *testing.T) {
	const retryAfter = "42"
	message := "TrustGate blocked this request: gateway burst rate limit exceeded. Retry in 42s."
	want := `{"error":{"message":"` + message + `","type":"rate_limit_error","code":"rate_limit_exceeded"}}`
	flat := []byte(`{"error":"rate limit exceeded","message":"Request blocked: rate limit exceeded.","reason":"burst","limit":100,"retry_after_seconds":42}`)
	headers := map[string][]string{
		"Retry-After":           {retryAfter},
		"X-RateLimit-Limit":     {"100"},
		"X-RateLimit-Remaining": {"0"},
		"X-RateLimit-Reason":    {"burst"},
	}

	t.Run("policy forwards the flat plan body", func(t *testing.T) {
		gatewayID := ids.New[ids.GatewayKind]()
		authID := ids.New[ids.AuthKind]()
		plugin := planBurstPlugin{err: &appplugins.PluginError{
			StatusCode: http.StatusTooManyRequests,
			Type:       "trustguard_rate_limited",
			Message:    "rate limit exceeded",
			Headers:    headers,
			Body:       flat,
		}}
		rc := planBurstConsumer(gatewayID, authID, []*policydomain.Policy{{
			ID:       ids.New[ids.PolicyKind](),
			Name:     "guard",
			Slug:     "trustguard",
			Enabled:  true,
			Priority: 1,
			Stages:   []policydomain.Stage{policydomain.StagePreRequest},
		}})
		app := fiber.New()
		app.Use(authStubRoutable(gatewayID, authID, rc))
		app.All("/*", proxyhttp.NewForwardedHandler(forwarderWithPolicies(t, plugin, nil)).Handle)

		resp := postChat(t, app)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "body: %s", raw)
		assert.Equal(t, retryAfter, resp.Header.Get("Retry-After"))
		assert.Equal(t, "100", resp.Header.Get("X-RateLimit-Limit"))
		assert.Equal(t, "burst", resp.Header.Get("X-RateLimit-Reason"))
		assert.JSONEq(t, want, string(raw))
		assert.NotContains(t, string(raw), `"reason"`)
	})

	t.Run("precheck limiter reaches the handler", func(t *testing.T) {
		gatewayID := ids.New[ids.GatewayKind]()
		authID := ids.New[ids.AuthKind]()
		limiter := ratelimitmocks.NewChecker(t)
		limiter.EXPECT().Check(mock.Anything, gatewayID).Return(&ratelimitapp.Exceeded{
			Reason:     ratelimitapp.ReasonBurst,
			Limit:      100,
			Remaining:  0,
			RetryAfter: 42 * time.Second,
		}).Once()
		rc := planBurstConsumer(gatewayID, authID, nil)
		app := fiber.New()
		app.Use(authStubRoutable(gatewayID, authID, rc))
		app.All("/*", proxyhttp.NewForwardedHandler(forwarderWithPolicies(t, planBurstPlugin{}, limiter)).Handle)

		resp := postChat(t, app)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "body: %s", raw)
		assert.Equal(t, retryAfter, resp.Header.Get("Retry-After"))
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.JSONEq(t, want, string(raw))
		assert.NotContains(t, string(raw), `"reason"`)
	})

	t.Run("policy dimension limit stays flat", func(t *testing.T) {
		gatewayID := ids.New[ids.GatewayKind]()
		authID := ids.New[ids.AuthKind]()
		body := []byte(`{"error":"rate limit exceeded","message":"TrustGate blocked this request: consumer rate limit exceeded (100 requests per 1m). Retry in 30s.","reason":"consumer","limit":100,"window":"1m","retry_after_seconds":30}`)
		plugin := planBurstPlugin{err: &appplugins.PluginError{
			StatusCode: http.StatusTooManyRequests,
			Message:    "rate limit exceeded",
			Headers:    map[string][]string{"Retry-After": {"30"}},
			Body:       body,
		}}
		rc := planBurstConsumer(gatewayID, authID, []*policydomain.Policy{{
			ID:       ids.New[ids.PolicyKind](),
			Name:     "rates",
			Slug:     "trustguard",
			Enabled:  true,
			Priority: 1,
		}})
		app := fiber.New()
		app.Use(authStubRoutable(gatewayID, authID, rc))
		app.All("/*", proxyhttp.NewForwardedHandler(forwarderWithPolicies(t, plugin, nil)).Handle)

		resp := postChat(t, app)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "body: %s", raw)
		assert.Equal(t, "30", resp.Header.Get("Retry-After"))
		assert.JSONEq(t, string(body), string(raw))
	})
}
