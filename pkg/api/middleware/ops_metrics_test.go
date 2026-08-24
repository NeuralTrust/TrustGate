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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type recordingOps struct {
	enabled   bool
	request   o11y.Request
	count     int
	spanNames []string
	finished  []o11y.SpanOutcome
}

func (r *recordingOps) Enabled() bool {
	return r.enabled
}

func (r *recordingOps) RecordRequest(_ context.Context, req o11y.Request) {
	r.request = req
	r.count++
}

func (r *recordingOps) StartRequestSpan(ctx context.Context, name string) (context.Context, o11y.RequestSpan) {
	r.spanNames = append(r.spanNames, name)
	return ctx, recordingSpan{ops: r}
}

type recordingSpan struct {
	ops *recordingOps
}

func (s recordingSpan) Finish(out o11y.SpanOutcome) {
	s.ops.finished = append(s.ops.finished, out)
}

func TestOpsMetricsMiddlewareRecordsOnlyBoundedValues(t *testing.T) {
	recorder := &recordingOps{enabled: true}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneAdmin).Middleware())
	app.Get("/v1/gateways/:id", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusForbidden)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/customer-id", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, 1, recorder.count)
	require.Equal(t, o11y.PlaneAdmin, recorder.request.Plane)
	require.Equal(t, o11y.RouteAdminGateways, recorder.request.Route)
	require.Equal(t, "GET", recorder.request.Method)
	require.Equal(t, "4xx", recorder.request.StatusClass)
	require.Equal(t, o11y.OutcomeDeniedForbidden, recorder.request.Outcome)
	require.NotContains(t, string(recorder.request.Route), "customer-id")
}

func TestOpsMetricsMiddlewareDisabledIsPassthrough(t *testing.T) {
	recorder := &recordingOps{}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneProxy).Middleware())
	app.Post("/*", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/private/path", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, 0, recorder.count)
	require.Empty(t, recorder.spanNames)
}

// A span name is a series in every trace backend, so it has to be as bounded as
// a metric attribute: consumer paths and ids must never reach it.
func TestOpsMetricsMiddlewareSpanNameStaysBounded(t *testing.T) {
	recorder := &recordingOps{enabled: true}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneAdmin).Middleware())
	app.Get("/v1/gateways/:id", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/customer-id?token=secret", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, []string{"GET admin.gateways"}, recorder.spanNames)
	require.Len(t, recorder.finished, 1)
	require.NotContains(t, recorder.spanNames[0], "customer-id")
	require.NotContains(t, recorder.spanNames[0], "secret")
	require.Equal(t, o11y.RouteAdminGateways, recorder.finished[0].Route)
	require.Equal(t, "2xx", recorder.finished[0].StatusClass)
}

func TestOpsMetricsMiddlewareSpanCarriesProductTraceID(t *testing.T) {
	const traceID = "11111111-2222-3333-4444-555555555555"
	recorder := &recordingOps{enabled: true}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneProxy).Middleware())
	app.Post("/*", func(c *fiber.Ctx) error {
		c.Set(HeaderTraceID, traceID)
		return c.SendStatus(fiber.StatusInternalServerError)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/forward", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Len(t, recorder.finished, 1)
	require.Equal(t, traceID, recorder.finished[0].TraceID)
	require.Equal(t, o11y.OutcomeServerError, recorder.finished[0].Outcome)
}

func TestOpsMetricsMiddlewareConnectRouteIsBounded(t *testing.T) {
	t.Parallel()

	const slug = "customer-secret-slug"
	recorder := &recordingOps{enabled: true}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneMCP).Middleware())
	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/"+slug+"/connect", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, o11y.RouteMCPOAuth, recorder.request.Route)
	require.NotContains(t, string(recorder.request.Route), slug)
}

func TestOpsMetricsMiddlewareConnectOutcomesRemainBounded(t *testing.T) {
	t.Parallel()

	const slug = "raw-api-key-sentinel"
	tests := []struct {
		status  int
		outcome o11y.Outcome
	}{
		{status: fiber.StatusSeeOther, outcome: o11y.OutcomeAllowed},
		{status: fiber.StatusUnauthorized, outcome: o11y.OutcomeDeniedAuth},
		{status: fiber.StatusTooManyRequests, outcome: o11y.OutcomeDeniedThrottled},
		{status: fiber.StatusInternalServerError, outcome: o11y.OutcomeServerError},
		{status: fiber.StatusServiceUnavailable, outcome: o11y.OutcomeServerError},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			t.Parallel()

			recorder := &recordingOps{enabled: true}
			app := fiber.New()
			app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneMCP).Middleware())
			app.Post("/:slug/connect", func(c *fiber.Ctx) error {
				return c.SendStatus(tt.status)
			})
			resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/"+slug+"/connect", nil))
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, o11y.RouteMCPOAuth, recorder.request.Route)
			require.Equal(t, tt.outcome, recorder.request.Outcome)
			require.NotContains(t, string(recorder.request.Route), slug)
		})
	}
}

func TestOpsMetricsMiddlewarePrefersBoundedLogicalOutcome(t *testing.T) {
	recorder := &recordingOps{enabled: true}
	app := fiber.New()
	app.Use(NewOpsMetricsMiddleware(recorder, o11y.PlaneMCP).Middleware())
	app.Post("/*", func(c *fiber.Ctx) error {
		SetOpsOutcome(c, o11y.OutcomeDeniedPolicy)
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/rpc/private-id", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, o11y.OutcomeDeniedPolicy, recorder.request.Outcome)
	require.Equal(t, o11y.RouteMCPRPC, recorder.request.Route)
}

func TestClassifyRouteUsesLinearEnums(t *testing.T) {
	tests := []struct {
		name  string
		plane o11y.Plane
		path  string
		want  o11y.Route
	}{
		{name: "health", plane: o11y.PlaneProxy, path: "/readyz", want: o11y.RouteHealth},
		{name: "version", plane: o11y.PlaneAdmin, path: "/__/version", want: o11y.RouteVersion},
		{name: "gateway id", plane: o11y.PlaneAdmin, path: "/v1/gateways/secret-id", want: o11y.RouteAdminGateways},
		{name: "gateway prefix boundary", plane: o11y.PlaneAdmin, path: "/v1/gateways-raw", want: o11y.RouteOther},
		{name: "catalog", plane: o11y.PlaneAdmin, path: "/v1/models-catalog", want: o11y.RouteAdminCatalog},
		{name: "config sync", plane: o11y.PlaneAdmin, path: "/v1/config-sync/connections", want: o11y.RouteAdminConfigSync},
		{name: "docs", plane: o11y.PlaneAdmin, path: "/docs/index.html", want: o11y.RouteAdminDocs},
		{name: "proxy", plane: o11y.PlaneProxy, path: "/tenant/private", want: o11y.RouteProxyForward},
		{name: "mcp rpc", plane: o11y.PlaneMCP, path: "/tenant/rpc", want: o11y.RouteMCPRPC},
		{name: "oauth", plane: o11y.PlaneMCP, path: "/oauth/token", want: o11y.RouteMCPOAuth},
		{name: "well known", plane: o11y.PlaneMCP, path: "/.well-known/oauth-protected-resource", want: o11y.RouteMCPOAuth},
		{name: "literal connect", plane: o11y.PlaneMCP, path: "/+/connect", want: o11y.RouteMCPOAuth},
		{name: "self service connect", plane: o11y.PlaneMCP, path: "/tools/connect", want: o11y.RouteMCPOAuth},
		{name: "nested mcp connect", plane: o11y.PlaneMCP, path: "/tools/mcp/connect", want: o11y.RouteMCPOAuth},
		{name: "root mcp connect", plane: o11y.PlaneMCP, path: "/mcp/connect", want: o11y.RouteMCPOAuth},
		{name: "root connect", plane: o11y.PlaneMCP, path: "/connect", want: o11y.RouteMCPRPC},
		{name: "empty slug connect", plane: o11y.PlaneMCP, path: "//connect", want: o11y.RouteMCPRPC},
		{name: "nested generic connect", plane: o11y.PlaneMCP, path: "/tools/other/connect", want: o11y.RouteMCPRPC},
		{name: "connect suffix extension", plane: o11y.PlaneMCP, path: "/tools/connect/extra", want: o11y.RouteMCPRPC},
		{name: "mcp segment prefix", plane: o11y.PlaneMCP, path: "/tools/notmcp/connect", want: o11y.RouteMCPRPC},
		{name: "oauth prefix boundary", plane: o11y.PlaneMCP, path: "/oauthish/token", want: o11y.RouteMCPRPC},
		{name: "well known prefix boundary", plane: o11y.PlaneMCP, path: "/.well-knownish/oauth", want: o11y.RouteMCPRPC},
		{name: "version is admin only", plane: o11y.PlaneProxy, path: "/__/version", want: o11y.RouteProxyForward},
		{name: "other", plane: o11y.PlaneAdmin, path: "/unknown/id", want: o11y.RouteOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, classifyRoute(tc.plane, tc.path))
		})
	}
}

func TestClassifyOutcomeUsesLinearEnums(t *testing.T) {
	tests := []struct {
		route  o11y.Route
		status int
		want   o11y.Outcome
	}{
		{route: o11y.RouteHealth, status: 503, want: o11y.OutcomeProbe},
		{route: o11y.RouteProxyForward, status: 200, want: o11y.OutcomeAllowed},
		{route: o11y.RouteProxyForward, status: 401, want: o11y.OutcomeDeniedAuth},
		{route: o11y.RouteProxyForward, status: 403, want: o11y.OutcomeDeniedForbidden},
		{route: o11y.RouteProxyForward, status: 429, want: o11y.OutcomeDeniedThrottled},
		{route: o11y.RouteProxyForward, status: 404, want: o11y.OutcomeClientError},
		{route: o11y.RouteProxyForward, status: 500, want: o11y.OutcomeServerError},
	}
	for _, tc := range tests {
		require.Equal(t, tc.want, classifyOutcome(tc.route, tc.status))
	}
}
