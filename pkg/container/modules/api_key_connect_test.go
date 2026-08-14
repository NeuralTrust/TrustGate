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

package modules

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	oauthhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	oauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/oauth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyConnectHandlerUsesMCPBaseDomainWithoutHeaderOverride(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	gateway := &gatewaydomain.Gateway{ID: gatewayID, Slug: "tenant"}
	finder := gatewaymocks.NewFinder(t)
	finder.EXPECT().FindBySlug(mock.Anything, "tenant").Return(gateway, nil).Once()

	connect := oauthmocks.NewAPIKeyConnectService(t)
	connect.EXPECT().ValidateTarget(mock.Anything, gatewayID, "tools").Return(nil).Once()

	cfg := &config.Config{
		Server: config.ServerConfig{
			GatewayBaseDomain: "gateway.test",
			MCPBaseDomain:     "mcp.test",
		},
	}
	c, err := container.New(
		container.WithModule(func(c *container.Container) error {
			if err := c.Provide(func() *config.Config { return cfg }); err != nil {
				return err
			}
			if err := c.Provide(func() appgateway.Finder { return finder }); err != nil {
				return err
			}
			if err := c.Provide(func() appoauth.APIKeyConnectService { return connect }); err != nil {
				return err
			}
			return c.Provide(func() appoauth.ConnectAttemptLimiter {
				return appoauth.NewNoopConnectAttemptLimiter()
			})
		}),
		container.WithModule(API),
	)
	require.NoError(t, err)

	var handler *oauthhttp.APIKeyConnectHandler
	require.NoError(t, c.Invoke(func(
		resolvedHandler *oauthhttp.APIKeyConnectHandler,
		globalResolver resolver.GatewayResolver,
	) {
		handler = resolvedHandler
		require.NotNil(t, globalResolver)
	}))
	require.NotNil(t, handler)

	app := fiber.New()
	app.Get("/:slug/connect", handler.Get)
	req := httptest.NewRequest(fiber.MethodGet, "/tools/connect", nil)
	req.Host = "tenant.mcp.test"
	req.Header.Set(resolver.HeaderGatewaySlug, "attacker")
	req.Header.Set(fiber.HeaderXForwardedHost, "attacker.mcp.test")
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, res.StatusCode)
	require.NoError(t, res.Body.Close())
}

func TestProvideConnectAttemptLimiterDisabledUsesNoop(t *testing.T) {
	t.Parallel()

	limiter := provideConnectAttemptLimiter(
		&config.Config{MCPConnectRateLimit: config.MCPConnectRateLimitConfig{Enabled: false}},
		cachemocks.NewClient(t),
		nil,
	)

	require.NoError(t, limiter.Check(
		context.Background(),
		appoauth.ConnectAttemptScopeSource,
		"",
	))
}

func TestProvideConnectAttemptLimiterEnabledUsesRedis(t *testing.T) {
	t.Parallel()

	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})
	cacheClient := cachemocks.NewClient(t)
	cacheClient.EXPECT().RedisClient().Return(client).Once()
	cfg := &config.Config{
		Server: config.ServerConfig{SecretKey: "module-secret"},
		MCPConnectRateLimit: config.MCPConnectRateLimitConfig{
			Enabled:       true,
			SourceLimit:   1,
			ConsumerLimit: 1,
			Window:        time.Minute,
		},
	}
	limiter := provideConnectAttemptLimiter(cfg, cacheClient, nil)

	require.NoError(t, limiter.Check(
		context.Background(),
		appoauth.ConnectAttemptScopeSource,
		"203.0.113.9",
	))
	var exceeded *appoauth.ConnectRateLimitExceeded
	require.ErrorAs(t, limiter.Check(
		context.Background(),
		appoauth.ConnectAttemptScopeSource,
		"203.0.113.9",
	), &exceeded)
}
