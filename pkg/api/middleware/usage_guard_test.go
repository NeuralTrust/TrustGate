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
	"io"
	"net/http/httptest"
	"testing"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixedChecker map[string]usagedomain.Reason

func (f fixedChecker) Exhausted(tenantID string) (usagedomain.Reason, bool) {
	reason, ok := f[tenantID]
	return reason, ok
}

func guardApp(t *testing.T, guard *UsageGuardMiddleware, tenant string, rt *trace.RequestTrace) *fiber.App {
	t.Helper()
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		gw := &gatewaydomain.Gateway{Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: tenant}}
		ctx := appgateway.WithGateway(c.UserContext(), gw)
		if rt != nil {
			ctx = trace.NewContext(ctx, rt)
		}
		c.SetUserContext(ctx)
		return c.Next()
	})
	app.Use(guard.Middleware())
	app.All("/*", func(c *fiber.Ctx) error { return c.SendString("served") })
	return app
}

func call(t *testing.T, app *fiber.App, path string) (int, []byte) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, path, nil))
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestUsageGuard(t *testing.T) {
	t.Parallel()
	on := func() bool { return true }
	off := func() bool { return false }
	checker := fixedChecker{"broke": usagedomain.ReasonWalletEmpty, "free": usagedomain.ReasonFreeLimitReached}

	t.Run("healthy tenant is served", func(t *testing.T) {
		t.Parallel()
		status, body := call(t, guardApp(t, NewUsageGuardMiddleware(checker, on), "fine", nil), "/X84Yhsy8/v1/chat/completions")
		assert.Equal(t, fiber.StatusOK, status)
		assert.Equal(t, "served", string(body))
	})
	t.Run("enforcement off serves exhausted tenants", func(t *testing.T) {
		t.Parallel()
		status, _ := call(t, guardApp(t, NewUsageGuardMiddleware(checker, off), "broke", nil), "/X84Yhsy8/v1/chat/completions")
		assert.Equal(t, fiber.StatusOK, status)
	})
	t.Run("no checker serves everyone", func(t *testing.T) {
		t.Parallel()
		status, _ := call(t, guardApp(t, NewUsageGuardMiddleware(nil, nil), "broke", nil), "/X84Yhsy8/v1/chat/completions")
		assert.Equal(t, fiber.StatusOK, status)
	})
	t.Run("empty wallet is 402 insufficient_funds in OpenAI envelope", func(t *testing.T) {
		t.Parallel()
		rt := trace.New("trace-1", trace.Metadata{})
		status, body := call(t, guardApp(t, NewUsageGuardMiddleware(checker, on), "broke", rt), "/X84Yhsy8/v1/chat/completions")
		assert.Equal(t, fiber.StatusPaymentRequired, status)
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &envelope), string(body))
		assert.Equal(t, ErrCodeInsufficientFunds, envelope.Error.Code)
		assert.NotEmpty(t, envelope.Error.Message)
		assert.Equal(t, ErrCodeInsufficientFunds, rt.StatusReason())
	})
	t.Run("free limit is 402 plan_limit", func(t *testing.T) {
		t.Parallel()
		rt := trace.New("trace-2", trace.Metadata{})
		status, _ := call(t, guardApp(t, NewUsageGuardMiddleware(checker, on), "free", rt), "/X84Yhsy8/v1/chat/completions")
		assert.Equal(t, fiber.StatusPaymentRequired, status)
		assert.Equal(t, ErrCodePlanLimit, rt.StatusReason())
	})
	t.Run("Anthropic route gets the Anthropic envelope", func(t *testing.T) {
		t.Parallel()
		status, body := call(t, guardApp(t, NewUsageGuardMiddleware(checker, on), "broke", nil), "/X84Yhsy8/v1/messages")
		assert.Equal(t, fiber.StatusPaymentRequired, status)
		var envelope struct {
			Type  string `json:"type"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &envelope), string(body))
		assert.Equal(t, "error", envelope.Type)
		assert.NotEmpty(t, envelope.Error.Message)
	})
	t.Run("MCP answers JSON-RPC on HTTP 402", func(t *testing.T) {
		t.Parallel()
		status, body := call(t, guardApp(t, NewUsageGuardMiddleware(checker, on).ForMCP(), "broke", nil), "/")
		assert.Equal(t, fiber.StatusPaymentRequired, status)
		var rpc struct {
			JSONRPC string `json:"jsonrpc"`
			ID      any    `json:"id"`
			Error   struct {
				Code int               `json:"code"`
				Data map[string]string `json:"data"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(body, &rpc), string(body))
		assert.Equal(t, "2.0", rpc.JSONRPC)
		assert.Nil(t, rpc.ID)
		assert.Equal(t, mcpUsageExhaustedCode, rpc.Error.Code)
		assert.Equal(t, ErrCodeInsufficientFunds, rpc.Error.Data["code"])
	})
}
