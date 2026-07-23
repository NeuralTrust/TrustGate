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

package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type stubGateChecker struct {
	last ids.GatewayID
	err  error
}

func (s *stubGateChecker) Check(_ context.Context, id ids.GatewayID) error {
	s.last = id
	return s.err
}

func TestPlanRateLimitForGatewayPrefersGatewayIDParam(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	policyID := ids.New[ids.PolicyKind]()
	limiter := &stubGateChecker{err: &ratelimitapp.Exceeded{
		Reason:     ratelimitapp.ReasonBurst,
		Limit:      60,
		Remaining:  0,
		RetryAfter: 5 * time.Second,
	}}
	m := NewPlanRateLimitMiddleware(limiter, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/policies/:id", func(c *fiber.Ctx) error {
		c.Locals(string(infracontext.TenantIDContextKey), "tenant-1")
		return m.ForGateway()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	path := "/v1/gateways/" + gatewayID.String() + "/policies/" + policyID.String()
	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, path, nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusTooManyRequests, resp.StatusCode)
	require.Equal(t, gatewayID, limiter.last)
	require.Equal(t, "burst", resp.Header.Get("X-RateLimit-Reason"))
}

func TestPlanRateLimitForGatewaySkipsPlatformJWT(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	limiter := &stubGateChecker{err: ratelimitapp.ErrUnavailable}
	m := NewPlanRateLimitMiddleware(limiter, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	app := fiber.New()
	app.Delete("/v1/gateways/:id", func(c *fiber.Ctx) error {
		c.Locals(string(infracontext.TenantIDContextKey), "")
		return m.ForGateway()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodDelete, "/v1/gateways/"+gatewayID.String(), nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.True(t, limiter.last.IsNil())
}

func TestPlanRateLimitForTenantUsesFinder(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	finder := gatewaymocks.NewFinder(t)
	finder.EXPECT().List(mock.Anything, domain.ListFilter{TenantID: "tenant-1", Page: 1, Size: 1}).
		Return([]*domain.Gateway{{ID: gatewayID}}, 1, nil).Once()

	limiter := &stubGateChecker{}
	m := NewPlanRateLimitMiddleware(limiter, finder, slog.New(slog.NewTextHandler(io.Discard, nil)))

	app := fiber.New()
	app.Get("/v1/providers-catalog", func(c *fiber.Ctx) error {
		c.Locals(string(infracontext.TenantIDContextKey), "tenant-1")
		return m.ForTenant()(c)
	}, func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/providers-catalog", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.Equal(t, gatewayID, limiter.last)
}
