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
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestAccessLogConnectOutcomesDoNotLeakRequestSecrets(t *testing.T) {
	t.Parallel()

	const (
		secret       = "raw-api-key-sentinel"
		opaqueTicket = "opaque-ticket-sentinel"
	)
	for _, status := range []int{
		fiber.StatusSeeOther,
		fiber.StatusUnauthorized,
		fiber.StatusTooManyRequests,
		fiber.StatusInternalServerError,
		fiber.StatusServiceUnavailable,
	} {
		status := status
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			app := fiber.New()
			app.Use(NewAccessLogMiddleware(logger).Middleware())
			app.Post("/tools/connect", func(c *fiber.Ctx) error {
				if status == fiber.StatusSeeOther {
					return c.Redirect("/tools/mcp/connect?ticket="+opaqueTicket, status)
				}
				return c.Status(status).SendString(http.StatusText(status))
			})
			req := httptest.NewRequest(
				fiber.MethodPost,
				"/tools/connect",
				strings.NewReader("api_key="+secret),
			)
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationForm)

			res, err := app.Test(req)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, res.Body)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())
			require.Equal(t, status, res.StatusCode)
			require.Contains(t, output.String(), `"status":`+strconv.Itoa(status))
			require.NotContains(t, output.String(), secret)
			require.NotContains(t, output.String(), "ticket=")
			require.NotContains(t, output.String(), opaqueTicket)
		})
	}
}

func TestAccessLogAttributesAdminCalls(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	app := fiber.New()
	app.Use(NewAccessLogMiddleware(slog.New(slog.NewJSONHandler(&output, nil))).Middleware())
	app.Get("/admin", func(c *fiber.Ctx) error {
		StoreAdminIdentity(c, AdminIdentity{Kind: AdminIdentityHuman, TenantID: "t1", Issuer: "neuraltrust-app"})
		return c.SendStatus(fiber.StatusOK)
	})
	app.Get("/public", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	for _, path := range []string{"/admin", "/public"} {
		resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, path, nil))
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], `"identity_kind":"human"`)
	require.Contains(t, lines[0], `"token_issuer":"neuraltrust-app"`)
	require.NotContains(t, lines[1], "identity_kind")
}

// A data-plane request is attributed in the default access log: the consumer
// it entered, the credential, the subject it runs as and the client a bearer
// token was issued to. A request nobody authenticated carries none of it.
func TestAccessLogAttributesDataPlaneCallers(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	authID := ids.New[ids.AuthKind]()
	var output bytes.Buffer
	app := fiber.New()
	app.Use(NewAccessLogMiddleware(slog.New(slog.NewJSONHandler(&output, nil))).Middleware())
	app.Post("/cons/v1/chat/completions", func(c *fiber.Ctx) error {
		ctx := appconsumer.WithGatewayID(c.UserContext(), gatewayID)
		ctx = appconsumer.WithConsumer(ctx, &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{ID: consumerID}})
		ctx = appauth.WithAuthContext(ctx, &appauth.AuthContext{Method: appauth.MethodOAuth2, AuthID: authID})
		ctx = identity.WithPrincipal(ctx, &identity.Principal{
			Subject: "agent-7",
			Method:  identity.MethodOAuth,
			Claims:  map[string]any{"azp": "agent-app", "email": "person@corp.example"},
		})
		c.SetUserContext(ctx)
		return c.SendStatus(fiber.StatusTooManyRequests)
	})
	app.Post("/anonymous", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusUnauthorized) })

	for _, path := range []string{"/cons/v1/chat/completions", "/anonymous"} {
		resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, path, nil))
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, 2)
	for _, want := range []string{
		`"gateway_id":"` + gatewayID.String() + `"`,
		`"consumer_id":"` + consumerID.String() + `"`,
		`"auth_id":"` + authID.String() + `"`,
		`"auth_method":"oauth2"`,
		`"principal_subject":"agent-7"`,
		`"client_id":"agent-app"`,
	} {
		require.Contains(t, lines[0], want)
	}
	require.NotContains(t, lines[0], "person@corp.example", "an email is not logged")
	require.NotContains(t, lines[1], "consumer_id")
	require.NotContains(t, lines[1], "principal_subject")
}
