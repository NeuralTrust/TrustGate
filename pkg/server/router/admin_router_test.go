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

package router_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	jwtmocks "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAdminRouterRefusesServiceCredentialsOnThePersonalKey(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	registries := []string{
		middleware.RequiredScope(middleware.ResourceRegistries, fiber.MethodGet),
		middleware.RequiredScope(middleware.ResourceRegistries, fiber.MethodPost),
	}
	credentials := map[string]*jwt.ServiceClaims{
		"eyJhbGciOiJSUzI1NiJ9.e30.bound": {TenantID: "t1", GatewayID: gatewayID.String(), Scopes: registries},
		"eyJhbGciOiJSUzI1NiJ9.e30.other": {TenantID: "t1", GatewayID: ids.New[ids.GatewayKind]().String(), Scopes: registries},
		"eyJhbGciOiJSUzI1NiJ9.e30.scope": {TenantID: "t1", GatewayID: gatewayID.String(), Scopes: []string{"consumers:read"}},
	}
	verifier := jwtmocks.NewServiceVerifier(t)
	verifier.EXPECT().Enabled().Return(true)
	verifier.EXPECT().Verify(mock.Anything).RunAndReturn(func(token string) (*jwt.ServiceClaims, error) {
		return credentials[token], nil
	})
	gateways := gatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).
		Return(&gatewaydomain.Gateway{ID: gatewayID, Metadata: gatewaydomain.WithTenantID(nil, "t1")}, nil)
	app := fiber.New()
	require.NoError(t, router.NewAdminRouter(router.AdminRouterDeps{
		MiddlewareTransport: middleware.NewTransport(),
		AdminAuth:           middleware.NewAdminAuthMiddleware(nil, nil, verifier, false),
		AdminAuthz:          middleware.NewAdminAuthzMiddleware(nil, gateways),
		StoreLLMKey:         storehttp.NewLLMKeyHandler(appauthmocks.NewPersonalKeys(t)),
	}).BuildRoutes(app))

	path := "/v1/gateways/" + gatewayID.String() + "/store/principal/llm-key"
	for token := range credentials {
		for _, route := range [][2]string{{http.MethodGet, path}, {http.MethodPost, path}, {http.MethodPost, path + "/rotate"}, {http.MethodDelete, path}} {
			req := httptest.NewRequest(route[0], route[1], strings.NewReader(`{"expires_at":"2099-01-01T00:00:00Z"}`))
			req.Header.Set(fiber.HeaderAuthorization, "Bearer "+token)
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			res, err := app.Test(req)
			require.NoError(t, err)
			raw, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())
			assert.Equal(t, http.StatusForbidden, res.StatusCode, "%s %s with %s: %s", route[0], route[1], token, raw)
			assert.Contains(t, string(raw), "Use a credential scoped to this gateway", "a route guard answers before the handler")
		}
	}
}
