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
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmetricsmocks "github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infrajwt "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const playgroundMetricsSecret = "playground-metrics-secret"

// TestMetricsMiddleware_PlaygroundVerdictComesFromTheResolver drives the real
// PlaygroundIdentityResolver ahead of the metrics middleware, in the order the
// proxy plane uses (Auth before Metrics), and checks the RequestContext handed
// to the worker: only a token the resolver verified yields PlaygroundVerified,
// and a forged token is refused before any telemetry is emitted.
func TestMetricsMiddleware_PlaygroundVerdictComesFromTheResolver(t *testing.T) {
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Slug: "cons1234", Active: true,
	}}
	res := resolver.NewPlaygroundIdentityResolver(
		infrajwt.NewPlaygroundVerifier(&config.ServerConfig{SecretKey: playgroundMetricsSecret}, nil))

	claims := &infrajwt.Claims{
		UserID:       "user-1",
		Purpose:      infrajwt.PurposePlayground,
		ConsumerSlug: rc.Consumer.Slug,
	}
	claims.ExpiresAt = golangjwt.NewNumericDate(time.Now().Add(5 * time.Minute))
	valid, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claims).
		SignedString([]byte(playgroundMetricsSecret))
	require.NoError(t, err)

	tests := []struct {
		name          string
		token         string
		wantProcessed bool
		want          bool
	}{
		{name: "token verified by the resolver", token: valid, wantProcessed: true, want: true},
		{name: "forged token rejected by the resolver", token: "forged", wantProcessed: false},
		{name: "no token", token: "", wantProcessed: true, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := appmetricsmocks.NewWorker(t)
			var (
				mu  sync.Mutex
				got *infracontext.RequestContext
			)
			if tt.wantProcessed {
				worker.EXPECT().
					Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Run(func(_ *trace.RequestTrace, req *infracontext.RequestContext, _ *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
						mu.Lock()
						defer mu.Unlock()
						got = req
					}).
					Return().
					Once()
			}

			cfg := &config.Config{}
			cfg.Telemetry.Enabled = true
			mw := middleware.NewMetricsMiddleware(worker, cfg)

			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gw.ID))
				return c.Next()
			})
			// Stands in for AuthMiddleware: a request carrying the header goes to
			// the real resolver (as ChainedIdentityResolver routes it) and is
			// refused when it does not verify; one without it passes unmarked.
			app.Use(func(c *fiber.Ctx) error {
				if c.Get(resolver.HeaderPlaygroundToken) == "" {
					return c.Next()
				}
				authCtx, err := res.Resolve(c, gw, rc)
				if err != nil {
					return c.SendStatus(fiber.StatusUnauthorized)
				}
				c.SetUserContext(appauth.WithAuthContext(c.UserContext(), authCtx))
				return c.Next()
			})
			app.Use(mw.Middleware())
			app.Post("/v1/chat/completions", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

			req := httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil)
			if tt.token != "" {
				req.Header.Set(resolver.HeaderPlaygroundToken, tt.token)
			}
			_, err := app.Test(req)
			require.NoError(t, err)

			mu.Lock()
			defer mu.Unlock()
			if !tt.wantProcessed {
				assert.Nil(t, got, "a refused request must emit no telemetry")
				return
			}
			require.NotNil(t, got, "worker.Process must be called")
			assert.Equal(t, tt.want, got.PlaygroundVerified)
		})
	}
}
