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
	"encoding/json"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

const (
	// ErrCodeInsufficientFunds is returned when a Standard tenant's wallet is
	// empty.
	ErrCodeInsufficientFunds = "insufficient_funds"
	// ErrCodePlanLimit is returned when a Free tenant reached a monthly limit.
	ErrCodePlanLimit = "plan_limit"

	usageBlockedMessage = "TrustGate blocked this request: the organization's usage is exhausted. Add funds or upgrade the plan to resume."

	// mcpUsageExhaustedCode is the JSON-RPC error code of an MCP request
	// refused for usage. It travels with HTTP 402, never 200, so the refused
	// call is not billed as usage.
	mcpUsageExhaustedCode = -32005
)

// UsageGuardMiddleware blocks the requests of tenants whose usage the control
// plane reports as exhausted. It runs after Metrics, so a blocked request is
// still visible in analytics with HTTP 402, and before anything that costs
// money, such as traffic labelling or the upstream call.
type UsageGuardMiddleware struct {
	checker appusage.ExhaustionChecker
	enabled func() bool
	mcp     bool
}

// NewUsageGuardMiddleware builds the guard. A nil checker or enabled function
// disables it, which is the case on every plane that is not fed by a control
// plane enforcing usage.
func NewUsageGuardMiddleware(checker appusage.ExhaustionChecker, enabled func() bool) *UsageGuardMiddleware {
	return &UsageGuardMiddleware{checker: checker, enabled: enabled}
}

// ForMCP returns a copy of the guard that answers in JSON-RPC.
func (m *UsageGuardMiddleware) ForMCP() *UsageGuardMiddleware {
	clone := *m
	clone.mcp = true
	return &clone
}

// Middleware returns the Fiber handler of the guard.
func (m *UsageGuardMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m.checker == nil || m.enabled == nil || !m.enabled() {
			return c.Next()
		}
		gw, ok := appgateway.FromContext(c.UserContext())
		if !ok {
			return c.Next()
		}
		reason, exhausted := m.checker.Exhausted(gw.TenantID())
		if !exhausted {
			return c.Next()
		}
		code := usageErrorCode(reason)
		if rt := trace.FromContext(c.UserContext()); rt != nil {
			rt.SetStatusReason(code)
		}
		SetOpsOutcome(c, o11y.OutcomeDeniedThrottled)
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		return c.Status(fiber.StatusPaymentRequired).Send(m.body(c, code))
	}
}

func (m *UsageGuardMiddleware) body(c *fiber.Ctx, code string) []byte {
	if m.mcp {
		out, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      nil,
			"error": map[string]any{
				"code":    mcpUsageExhaustedCode,
				"message": usageBlockedMessage,
				"data":    map[string]string{"code": code},
			},
		})
		return out
	}
	route, ok := proxyRouteFor(c)
	if !ok || route.IsBedrockNative() {
		out, _ := json.Marshal(httpio.ErrorBody{Error: code, Message: usageBlockedMessage})
		return out
	}
	format := route.RequestFormat()
	if format == "" || adapter.OpenAIErrorDialect(format) {
		return adapter.EncodeOpenAIGatewayError(fiber.StatusPaymentRequired, code, usageBlockedMessage)
	}
	return adapter.EncodeErrorBody(format, fiber.StatusPaymentRequired, usageBlockedMessage)
}

func usageErrorCode(reason usagedomain.Reason) string {
	if reason == usagedomain.ReasonFreeLimitReached {
		return ErrCodePlanLimit
	}
	return ErrCodeInsufficientFunds
}
