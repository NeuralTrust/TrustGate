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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/gofiber/fiber/v2"
)

const opsOutcomeKey = "trustgate.ops.outcome"

// OpsMetricsMiddleware records bounded RED and outcome metrics for one plane.
type OpsMetricsMiddleware struct {
	recorder o11y.RequestRecorder
	plane    o11y.Plane
}

// NewOpsMetricsMiddleware binds operational metrics to a fixed plane.
func NewOpsMetricsMiddleware(recorder o11y.RequestRecorder, plane o11y.Plane) *OpsMetricsMiddleware {
	return &OpsMetricsMiddleware{recorder: recorder, plane: plane}
}

// Middleware returns a Fiber handler that never records raw request data.
func (m *OpsMetricsMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m == nil || m.recorder == nil || !m.recorder.Enabled() {
			return c.Next()
		}
		start := time.Now()
		err := c.Next()
		status := c.Response().StatusCode()
		if err != nil {
			status = fiber.StatusInternalServerError
			var fiberErr *fiber.Error
			if errors.As(err, &fiberErr) {
				status = fiberErr.Code
			}
		}
		route := classifyRoute(m.plane, c.Path())
		outcome := classifyOutcome(route, status)
		if marked, ok := c.Locals(opsOutcomeKey).(o11y.Outcome); ok {
			outcome = marked
		}
		m.recorder.RecordRequest(c.UserContext(), o11y.Request{
			Plane:       m.plane,
			Route:       route,
			Method:      boundedMethod(c.Method()),
			StatusClass: statusClass(status),
			Outcome:     outcome,
			Duration:    time.Since(start),
		})
		return err
	}
}

// SetOpsOutcome records a bounded logical outcome for protocols whose errors
// are not represented by the HTTP status.
func SetOpsOutcome(c *fiber.Ctx, outcome o11y.Outcome) {
	c.Locals(opsOutcomeKey, outcome)
}

func classifyRoute(plane o11y.Plane, path string) o11y.Route {
	switch {
	case path == "/health", path == "/healthz", path == "/readyz":
		return o11y.RouteHealth
	case plane == o11y.PlaneAdmin && path == "/__/version":
		return o11y.RouteVersion
	}
	switch plane {
	case o11y.PlaneAdmin:
		switch {
		case path == "/v1/gateways", strings.HasPrefix(path, "/v1/gateways/"):
			return o11y.RouteAdminGateways
		case path == "/v1/providers-catalog", path == "/v1/models-catalog",
			path == "/v1/policies-catalog", path == "/v1/mcp-servers-catalog":
			return o11y.RouteAdminCatalog
		case path == "/v1/config-sync/connections":
			return o11y.RouteAdminConfigSync
		case path == "/docs", strings.HasPrefix(path, "/docs/"):
			return o11y.RouteAdminDocs
		}
	case o11y.PlaneProxy:
		return o11y.RouteProxyForward
	case o11y.PlaneMCP:
		if strings.HasPrefix(path, "/oauth/") ||
			strings.HasPrefix(path, "/.well-known/") ||
			path == "/+/connect" ||
			isSelfServiceConnectPath(path) ||
			strings.HasSuffix(path, "/mcp/connect") {
			return o11y.RouteMCPOAuth
		}
		return o11y.RouteMCPRPC
	}
	return o11y.RouteOther
}

func isSelfServiceConnectPath(path string) bool {
	if !strings.HasPrefix(path, "/") ||
		!strings.HasSuffix(path, "/connect") ||
		strings.Count(path, "/") != 2 {
		return false
	}
	slug := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/connect")
	return slug != ""
}

func boundedMethod(method string) string {
	switch method {
	case fiber.MethodGet, fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch,
		fiber.MethodDelete, fiber.MethodOptions, fiber.MethodHead:
		return method
	default:
		return "OTHER"
	}
}

func statusClass(status int) string {
	if status < 100 || status > 599 {
		return "other"
	}
	return fmt.Sprintf("%dxx", status/100)
}

func classifyOutcome(route o11y.Route, status int) o11y.Outcome {
	if route == o11y.RouteHealth {
		return o11y.OutcomeProbe
	}
	switch {
	case status == fiber.StatusUnauthorized:
		return o11y.OutcomeDeniedAuth
	case status == fiber.StatusForbidden:
		return o11y.OutcomeDeniedForbidden
	case status == fiber.StatusTooManyRequests:
		return o11y.OutcomeDeniedThrottled
	case status >= 500:
		return o11y.OutcomeServerError
	case status >= 400:
		return o11y.OutcomeClientError
	default:
		return o11y.OutcomeAllowed
	}
}
