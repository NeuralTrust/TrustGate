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
	"log/slog"
	"strconv"
	"strings"

	appratelimit "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Routes classified as credential traffic. They are matched by prefix rather
// than listed one by one so a new OAuth route arrives in the tighter class by
// default — the failure mode of forgetting is then a limit that is too strict,
// which someone reports, rather than one that is absent, which nobody does.
const (
	oauthPathPrefix = "/oauth/"
	// Brand images are static and cacheable; they sit under /oauth/ only
	// because the connect page serves them.
	oauthBrandPathPrefix = "/oauth/brands/"
	// whoAmIPath is spelled here rather than imported: the handler package
	// imports this one, so the constant cannot travel the other way.
	whoAmIPath = "/whoami"
)

// SourceResolver names the origin of a request, honouring X-Forwarded-For only
// as far back as the configured trusted proxies.
type SourceResolver func(peer, forwardedFor string) string

// MCPPlaneRateLimitMiddleware is the MCP plane's floor: what one origin may
// send before it has proved anything.
//
// It runs on the base transport, ahead of authentication, because the routes
// most worth guessing at are the ones that answer before a credential is
// known — dynamic client registration, the token exchange, the authorize
// redirect, /whoami. The plan limit cannot cover them: it is keyed by gateway
// and checked inside the RPC dispatcher, so it only ever sees requests that
// already resolved a consumer, and charging anonymous abuse to a customer's
// monthly quota would make a flood their outage and their bill.
//
// It fails open. A counter that takes the plane down with it when Redis blinks
// is a worse outage than the one it prevents, so an unreachable limiter is
// logged and counted, not enforced.
type MCPPlaneRateLimitMiddleware struct {
	limiter       appratelimit.PlaneLimiter
	resolveSource SourceResolver
	enabled       bool
	logger        *slog.Logger
	failOpen      metric.Int64Counter
}

func NewMCPPlaneRateLimitMiddleware(
	limiter appratelimit.PlaneLimiter,
	resolveSource SourceResolver,
	enabled bool,
	logger *slog.Logger,
) *MCPPlaneRateLimitMiddleware {
	if logger == nil {
		logger = slog.Default()
	}
	failOpen, err := otel.Meter("trustgate/ratelimit").Int64Counter(
		"trustgate_mcp_plane_rate_limit_fail_open_total",
		metric.WithDescription("MCP plane rate limit checks that could not be counted and were allowed"),
	)
	if err != nil {
		failOpen = nil
	}
	return &MCPPlaneRateLimitMiddleware{
		limiter:       limiter,
		resolveSource: resolveSource,
		enabled:       enabled,
		logger:        logger,
		failOpen:      failOpen,
	}
}

func (m *MCPPlaneRateLimitMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m == nil || !m.enabled || m.limiter == nil || m.resolveSource == nil {
			return c.Next()
		}
		source := m.resolveSource(c.Context().RemoteAddr().String(), c.Get(fiber.HeaderXForwardedFor))
		if source == "" {
			return c.Next()
		}

		// The host is part of the subject so two gateways served by the same
		// deployment keep separate buckets: one being flooded must not spend
		// the other's allowance.
		class := classifyPlaneRoute(c.Path())
		err := m.limiter.Check(c.UserContext(), class, c.Hostname()+"|"+source)
		if err == nil {
			return c.Next()
		}

		var exceeded *appratelimit.PlaneLimitExceeded
		if errors.As(err, &exceeded) {
			return writePlaneRateLimited(c, exceeded)
		}

		m.logger.Warn("mcp plane rate limit: counter unavailable; fail-open",
			slog.String("path", c.Path()),
			slog.Any("error", err))
		if m.failOpen != nil {
			m.failOpen.Add(c.UserContext(), 1, metric.WithAttributes(
				attribute.String("class", planeClassName(class)),
			))
		}
		return c.Next()
	}
}

// classifyPlaneRoute decides which bucket a path is counted in. Everything
// under /oauth/ mints, exchanges or verifies a credential, and /whoami answers
// whether an api key is real; the rest of the plane is read-mostly or is the
// authenticated surface, which the plan limit meters again per tenant.
func classifyPlaneRoute(path string) appratelimit.PlaneClass {
	if path == whoAmIPath {
		return appratelimit.PlaneClassCredential
	}
	if strings.HasPrefix(path, oauthBrandPathPrefix) {
		return appratelimit.PlaneClassDefault
	}
	if strings.HasPrefix(path, oauthPathPrefix) {
		return appratelimit.PlaneClassCredential
	}
	return appratelimit.PlaneClassDefault
}

func planeClassName(class appratelimit.PlaneClass) string {
	if class == appratelimit.PlaneClassCredential {
		return "credential"
	}
	return "default"
}

// writePlaneRateLimited answers in HTTP, not JSON-RPC: this limit is refused
// before the request is parsed, let alone dispatched, and every client — an
// MCP transport, a browser mid-redirect, curl — understands 429 and
// Retry-After. The plan limit, which runs after dispatch, answers in JSON-RPC.
func writePlaneRateLimited(c *fiber.Ctx, exceeded *appratelimit.PlaneLimitExceeded) error {
	seconds := int(exceeded.RetryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	c.Set(fiber.HeaderRetryAfter, strconv.Itoa(seconds))
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"error":   "rate_limited",
		"message": "too many requests; retry after " + strconv.Itoa(seconds) + "s",
	})
}
