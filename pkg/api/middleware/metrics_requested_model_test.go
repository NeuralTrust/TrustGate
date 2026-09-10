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

package middleware_test

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmetricsmocks "github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const multipartAudioBody = "--x\r\n" +
	"Content-Disposition: form-data; name=\"model\"\r\n\r\n" +
	"whisper-1\r\n" +
	"--x\r\n" +
	"Content-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n" +
	"Content-Type: audio/wav\r\n\r\n" +
	"\x00\x01\x02\r\n" +
	"--x--\r\n"

func TestMetricsMiddleware_StampsRequestedModelOnRejectedRequests(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		body             string
		contentType      string
		status           int
		errorCode        string
		locals           *resolver.ProxyRoute
		wantModel        string
		wantSourceFormat adapter.Format
	}{
		{
			name:             "model denied by the allowlist",
			path:             "/support/v1/chat/completions",
			body:             `{"model":"gpt-4.1-nano","messages":[]}`,
			contentType:      fiber.MIMEApplicationJSON,
			status:           fiber.StatusForbidden,
			errorCode:        "model_not_allowed",
			wantModel:        "gpt-4.1-nano",
			wantSourceFormat: adapter.FormatOpenAI,
		},
		{
			name:             "auth rejection before routing",
			path:             "/support/v1/chat/completions",
			body:             `{"model":"gpt-4o","messages":[]}`,
			contentType:      fiber.MIMEApplicationJSON,
			status:           fiber.StatusUnauthorized,
			errorCode:        "unauthenticated",
			wantModel:        "gpt-4o",
			wantSourceFormat: adapter.FormatOpenAI,
		},
		{
			name:             "auto with a failing upstream",
			path:             "/support/v1/chat/completions",
			body:             `{"model":"auto","messages":[]}`,
			contentType:      fiber.MIMEApplicationJSON,
			status:           fiber.StatusBadGateway,
			errorCode:        "upstream_error",
			wantModel:        "auto",
			wantSourceFormat: adapter.FormatOpenAI,
		},
		{
			name:             "gemini model encoded in the path",
			path:             "/support/v1beta/models/gemini-2.5-flash:generateContent",
			body:             `{"contents":[{"parts":[{"text":"hi"}]}]}`,
			contentType:      fiber.MIMEApplicationJSON,
			status:           fiber.StatusForbidden,
			errorCode:        "model_not_allowed",
			wantModel:        "gemini-2.5-flash",
			wantSourceFormat: adapter.FormatGemini,
		},
		{
			name:             "multipart audio transcription body",
			path:             "/support/v1/audio/transcriptions",
			body:             multipartAudioBody,
			contentType:      "multipart/form-data; boundary=x",
			status:           fiber.StatusForbidden,
			errorCode:        "model_not_allowed",
			wantModel:        "whisper-1",
			wantSourceFormat: adapter.FormatOpenAIAudio,
		},
		{
			// The production path: Auth already resolved the route, so the
			// Locals value is what stamps the snapshot. The seeded format
			// disagrees with what ResolveProxyPath would return for this path,
			// so only the Locals branch can produce this result.
			name:        "route already resolved into Locals wins over the path",
			path:        "/support/v1/chat/completions",
			body:        `{"model":"claude-sonnet-4-5","messages":[]}`,
			contentType: fiber.MIMEApplicationJSON,
			status:      fiber.StatusForbidden,
			errorCode:   "model_not_allowed",
			locals: &resolver.ProxyRoute{
				ConsumerSlug: "support",
				SourceFormat: adapter.FormatAnthropic,
				Capability:   resolver.CapabilityChat,
				Rest:         resolver.RouteMessages,
			},
			wantModel:        "claude-sonnet-4-5",
			wantSourceFormat: adapter.FormatAnthropic,
		},
		{
			// A path ResolveProxyPath cannot parse: without the Locals branch
			// the snapshot would carry no source format at all.
			name:        "unparseable path still stamped from Locals",
			path:        "/support/v1/some/extension/route",
			body:        `{"model":"gpt-4o","messages":[]}`,
			contentType: fiber.MIMEApplicationJSON,
			status:      fiber.StatusNotFound,
			errorCode:   "not_found",
			locals: &resolver.ProxyRoute{
				ConsumerSlug: "support",
				SourceFormat: adapter.FormatOpenAI,
				Capability:   resolver.CapabilityChat,
				Rest:         "/v1/some/extension/route",
			},
			wantModel:        "gpt-4o",
			wantSourceFormat: adapter.FormatOpenAI,
		},
		{
			// The same unparseable path with nothing in Locals: the fallback
			// resolver fails and the format stays empty, which is what makes
			// the row above load-bearing.
			name:        "unparseable path with no Locals leaves the format empty",
			path:        "/support/v1/some/extension/route",
			body:        `{"model":"gpt-4o","messages":[]}`,
			contentType: fiber.MIMEApplicationJSON,
			status:      fiber.StatusNotFound,
			errorCode:   "not_found",
			wantModel:   "gpt-4o",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			worker := appmetricsmocks.NewWorker(t)
			var (
				mu     sync.Mutex
				gotReq *infracontext.RequestContext
			)
			worker.EXPECT().
				Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Run(func(_ *trace.RequestTrace, req *infracontext.RequestContext, _ *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
					mu.Lock()
					defer mu.Unlock()
					gotReq = req
				}).
				Return().
				Once()

			cfg := &config.Config{}
			cfg.Telemetry.Enabled = true
			mw := middleware.NewMetricsMiddleware(worker, cfg)

			gatewayID := ids.New[ids.GatewayKind]()
			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gatewayID))
				if tc.locals != nil {
					c.Locals(resolver.ProxyRouteLocalsKey, *tc.locals)
				}
				return c.Next()
			})
			app.Use(mw.Middleware())
			app.All("/*", func(c *fiber.Ctx) error {
				return c.Status(tc.status).JSON(fiber.Map{"error": tc.errorCode})
			})

			httpReq := httptest.NewRequest(fiber.MethodPost, tc.path, strings.NewReader(tc.body))
			httpReq.Header.Set(fiber.HeaderContentType, tc.contentType)
			resp, err := app.Test(httpReq)
			require.NoError(t, err)
			require.Equal(t, tc.status, resp.StatusCode)

			mu.Lock()
			defer mu.Unlock()
			require.NotNil(t, gotReq, "worker.Process must receive a request context")
			assert.Equal(t, tc.wantModel, gotReq.RequestedModel)
			assert.Equal(t, string(tc.wantSourceFormat), gotReq.SourceFormat)
			assert.Equal(t, tc.body, string(gotReq.Body), "the snapshot must keep the client body")
		})
	}
}
