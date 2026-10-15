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

type OpsMetricsMiddleware struct {
	recorder o11y.RequestRecorder
	plane    o11y.Plane
}

func NewOpsMetricsMiddleware(recorder o11y.RequestRecorder, plane o11y.Plane) *OpsMetricsMiddleware {
	return &OpsMetricsMiddleware{recorder: recorder, plane: plane}
}

func (m *OpsMetricsMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m == nil || m.recorder == nil || !m.recorder.Enabled() {
			return c.Next()
		}
		// The route classification is bounded and depends only on the request
		// path, so it can name the span before the handler runs.
		route := classifyRoute(m.plane, c.Path())
		method := boundedMethod(c.Method())
		ctx, span := m.recorder.StartRequestSpan(c.UserContext(), method+" "+string(route), route)
		c.SetUserContext(ctx)

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
		outcome := classifyOutcome(route, status)
		if marked, ok := c.Locals(opsOutcomeKey).(o11y.Outcome); ok {
			outcome = marked
		}
		request := o11y.Request{
			Plane:       m.plane,
			Route:       route,
			Method:      method,
			StatusClass: statusClass(status),
			Outcome:     outcome,
			Duration:    time.Since(start),
		}
		m.recorder.RecordRequest(c.UserContext(), request)
		// Cloned for the same reason boundedMethod returns a constant: the header
		// value is a view of the response buffer, which is reused by the next
		// request, while the span holds the attribute until the batch exporter
		// ships it. Uncloned, one exported span carried a trace id whose first
		// seven bytes had become the string "nosniff" from a later response's
		// X-Content-Type-Options header.
		span.Finish(o11y.SpanOutcome{Request: request, TraceID: strings.Clone(c.GetRespHeader(HeaderTraceID))})
		return err
	}
}

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

// boundedMethod maps a request method onto a fixed set, and returns the package
// CONSTANT rather than echoing its argument.
//
// That is the whole point of the rewrite. c.Method() is a zero-copy view of
// fasthttp's request buffer, which is reused by the next request on the same
// connection. Returning it here handed that view to the metric attribute set and
// the span name, where the OTel SDK retains it for the lifetime of the process:
// the bytes then changed underneath, producing methods that were never sent
// ("GETT", "POS", "GETETE") and stranding the accumulating series behind a key
// that no longer matches itself, so a second one started beside it.
//
// A constant cannot be mutated by anyone, and unlike strings.Clone it allocates
// nothing on a per-request path. Elsewhere in this package the same hazard is
// handled with strings.Clone, which is the right tool when the value is not from
// a fixed set.
func boundedMethod(method string) string {
	switch method {
	case fiber.MethodGet:
		return fiber.MethodGet
	case fiber.MethodPost:
		return fiber.MethodPost
	case fiber.MethodPut:
		return fiber.MethodPut
	case fiber.MethodPatch:
		return fiber.MethodPatch
	case fiber.MethodDelete:
		return fiber.MethodDelete
	case fiber.MethodOptions:
		return fiber.MethodOptions
	case fiber.MethodHead:
		return fiber.MethodHead
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
