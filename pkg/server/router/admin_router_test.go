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
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	configsynchttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync"
	keygrouphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/keygroup"
	playgroundhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/playground"
	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	revokermocks "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation/mocks"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/app/gateway/mocks"
	keygroupmocks "github.com/NeuralTrust/TrustGate/pkg/app/keygroup/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	jwtmocks "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
	golangjwt "github.com/golang-jwt/jwt/v5"
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
	forUser := "/v1/gateways/" + gatewayID.String() + "/store/users/bob/llm-key"
	everyKey := "/v1/gateways/" + gatewayID.String() + "/store/principal/llm-keys"
	oneKey := everyKey + "/" + ids.New[ids.AuthKind]().String()
	for token := range credentials {
		for _, route := range [][2]string{
			{http.MethodGet, path}, {http.MethodPost, path}, {http.MethodPost, path + "/rotate"}, {http.MethodDelete, path}, {http.MethodPost, forUser},
			{http.MethodGet, everyKey}, {http.MethodPost, oneKey + "/rotate"}, {http.MethodDelete, oneKey},
		} {
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

func TestAdminRouterRefusesServiceCredentialsOnDirectoryGroups(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	write := middleware.RequiredScope(middleware.ResourceAuths, fiber.MethodPut)
	token := "eyJhbGciOiJSUzI1NiJ9.e30.auths-write"
	verifier := jwtmocks.NewServiceVerifier(t)
	verifier.EXPECT().Enabled().Return(true)
	verifier.EXPECT().Verify(mock.Anything).Return(&jwt.ServiceClaims{
		TenantID: "t1", GatewayID: gatewayID.String(), Scopes: []string{write},
	}, nil)
	gateways := gatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).
		Return(&gatewaydomain.Gateway{ID: gatewayID, Metadata: gatewaydomain.WithTenantID(nil, "t1")}, nil)
	app := fiber.New()
	require.NoError(t, router.NewAdminRouter(router.AdminRouterDeps{
		MiddlewareTransport:   middleware.NewTransport(),
		AdminAuth:             middleware.NewAdminAuthMiddleware(nil, nil, verifier, false),
		AdminAuthz:            middleware.NewAdminAuthzMiddleware(nil, gateways),
		UpdateAuthOwnerGroups: authhttp.NewUpdateAuthOwnerGroupsHandler(nil, nil, nil, nil, nil),
		UpdateSubjectGroups:   authhttp.NewUpdateSubjectGroupsHandler(nil, nil),
	}).BuildRoutes(app))

	routes := []string{
		"/v1/gateways/" + gatewayID.String() + "/auths/" + ids.New[ids.AuthKind]().String() + "/groups",
		"/v1/gateways/" + gatewayID.String() + "/subjects/user-1/groups",
	}
	for _, path := range routes {
		req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"groups":["eng"]}`))
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+token)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		res, err := app.Test(req)
		require.NoError(t, err)
		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		assert.Equal(t, http.StatusForbidden, res.StatusCode, "%s: %s", path, raw)
		assert.Contains(t, string(raw), "Use a credential scoped to this gateway")
	}
}

// A service credential scoped to the gateway's auths may read its group
// budgets, never write them: a budget is set by a person, in the console.
func TestAdminRouterKeepsGroupBudgetWritesFromServiceCredentials(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	token := "eyJhbGciOiJSUzI1NiJ9.e30.auths"
	verifier := jwtmocks.NewServiceVerifier(t)
	verifier.EXPECT().Enabled().Return(true)
	verifier.EXPECT().Verify(token).Return(&jwt.ServiceClaims{
		TenantID: "t1", GatewayID: gatewayID.String(), Scopes: []string{
			middleware.RequiredScope(middleware.ResourceAuths, fiber.MethodGet),
			middleware.RequiredScope(middleware.ResourceAuths, fiber.MethodPut),
			middleware.RequiredScope(middleware.ResourceAuths, fiber.MethodDelete),
		},
	}, nil)
	gateways := gatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).
		Return(&gatewaydomain.Gateway{ID: gatewayID, Metadata: gatewaydomain.WithTenantID(nil, "t1")}, nil)
	budgets := keygroupmocks.NewBudgets(t)
	budgets.EXPECT().List(mock.Anything, gatewayID).Return([]*keygroupdomain.Budget{}, nil).Once()
	app := fiber.New()
	require.NoError(t, router.NewAdminRouter(router.AdminRouterDeps{
		MiddlewareTransport: middleware.NewTransport(),
		AdminAuth:           middleware.NewAdminAuthMiddleware(nil, nil, verifier, false),
		AdminAuthz:          middleware.NewAdminAuthzMiddleware(nil, gateways),
		KeyGroupBudgets:     keygrouphttp.NewBudgetHandler(budgets),
	}).BuildRoutes(app))

	base := "/v1/gateways/" + gatewayID.String() + "/key-groups"
	for _, route := range [][3]any{
		{http.MethodGet, base + "/budgets", http.StatusOK},
		{http.MethodPut, base + "/g-eng/budget", http.StatusForbidden},
		{http.MethodDelete, base + "/g-eng/budget", http.StatusForbidden},
	} {
		req := httptest.NewRequest(route[0].(string), route[1].(string), strings.NewReader(`{"monthly_limit_usd":10,"action":"block"}`))
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+token)
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		res, err := app.Test(req)
		require.NoError(t, err)
		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		assert.Equal(t, route[2], res.StatusCode, "%s %s: %s", route[0], route[1], raw)
	}
}

// A service credential with auths:write is bound to one gateway. Offboarding
// does not use it: the app sends the console JWT. The route must refuse the
// machine token before the handler runs.
func TestAdminRouterRefusesServiceCredentialsOnSubjectSessions(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	write := middleware.RequiredScope(middleware.ResourceAuths, fiber.MethodDelete)
	token := "eyJhbGciOiJSUzI1NiJ9.e30.sessions"
	verifier := jwtmocks.NewServiceVerifier(t)
	verifier.EXPECT().Enabled().Return(true)
	verifier.EXPECT().Verify(token).Return(&jwt.ServiceClaims{
		TenantID: "t1", GatewayID: gatewayID.String(), Scopes: []string{write},
	}, nil)
	gateways := gatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).
		Return(&gatewaydomain.Gateway{ID: gatewayID, Metadata: gatewaydomain.WithTenantID(nil, "t1")}, nil)
	app := fiber.New()
	require.NoError(t, router.NewAdminRouter(router.AdminRouterDeps{
		MiddlewareTransport: middleware.NewTransport(),
		AdminAuth:           middleware.NewAdminAuthMiddleware(nil, nil, verifier, false),
		AdminAuthz:          middleware.NewAdminAuthzMiddleware(nil, gateways),
		DeleteSubjectSessions: authhttp.NewDeleteSubjectSessionsHandler(
			subjectSessionsMustNotRun{},
			nil,
			nil,
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		),
	}).BuildRoutes(app))

	req := httptest.NewRequest(http.MethodDelete, "/v1/gateways/"+gatewayID.String()+"/subjects/user-1/sessions", nil)
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+token)
	res, err := app.Test(req)
	require.NoError(t, err)
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	assert.Equal(t, http.StatusForbidden, res.StatusCode, string(raw))
	assert.Contains(t, string(raw), "Use a credential scoped to this gateway")
}

func TestAdminRouterRefusesServiceCredentialsOnConfigSyncRevocations(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	write := middleware.RequiredScope(middleware.ResourceGateways, fiber.MethodPost)
	bearer := "eyJhbGciOiJSUzI1NiJ9.e30.revocations"
	verifier := jwtmocks.NewServiceVerifier(t)
	verifier.EXPECT().Enabled().Return(true)
	verifier.EXPECT().Verify(bearer).Return(&jwt.ServiceClaims{
		TenantID: "t1", GatewayID: gatewayID.String(), Scopes: []string{write},
	}, nil)
	gateways := gatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, gatewayID).
		Return(&gatewaydomain.Gateway{ID: gatewayID, Metadata: gatewaydomain.WithTenantID(nil, "t1")}, nil)
	app := fiber.New()
	require.NoError(t, router.NewAdminRouter(router.AdminRouterDeps{
		MiddlewareTransport:    middleware.NewTransport(),
		AdminAuth:              middleware.NewAdminAuthMiddleware(nil, nil, verifier, false),
		AdminAuthz:             middleware.NewAdminAuthzMiddleware(nil, gateways),
		RevokeConfigSyncTokens: configsynchttp.NewRevokeTokensHandler(revokermocks.NewRevoker(t)),
	}).BuildRoutes(app))

	req := httptest.NewRequest(http.MethodPost, "/v1/gateways/"+gatewayID.String()+"/config-sync/revocations",
		strings.NewReader(`{"jtis":["a1"]}`))
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+bearer)
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	res, err := app.Test(req)
	require.NoError(t, err)
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	assert.Equal(t, http.StatusForbidden, res.StatusCode, string(raw))
}

type subjectSessionsMustNotRun struct{}

func (subjectSessionsMustNotRun) RevokeSubjectSessions(context.Context, string, string, string) (int, error) {
	return 0, errors.New("handler must not run")
}

// signConsoleToken mints an HS256 console JWT, the kind issued by the app to a
// signed-in person. An empty tenantID yields a platform token, same as
// resolveConsoleIdentity treats any other caller with no tenant_id claim.
func signConsoleToken(t *testing.T, secret, tenantID string) string {
	t.Helper()
	claims := &jwt.Claims{
		TenantID: tenantID,
		UserID:   "user-1",
		RegisteredClaims: golangjwt.RegisteredClaims{
			ExpiresAt: golangjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}
	token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return token
}

type fakeConnectionLister struct {
	byScope map[string][]configsyncconn.Connection
}

func (f fakeConnectionLister) List(_ context.Context, scope string, _ *listing.Page) ([]configsyncconn.Connection, error) {
	return f.byScope[scope], nil
}

// TestAdminRouterScopesConfigSyncConnectionsToCallerTenant is a regression test
// for the full route (auth + RequireConfigSyncScopeAccess + handler): a tenant
// caller must name one of its own gateways in ?scope= and is refused a foreign
// one, while a platform caller may list every data plane unscoped.
func TestAdminRouterScopesConfigSyncConnectionsToCallerTenant(t *testing.T) {
	t.Parallel()
	const secret = "secret"
	ownGateway := ids.New[ids.GatewayKind]()
	foreignGateway := ids.New[ids.GatewayKind]()

	gateways := gatewaymocks.NewFinder(t)
	gateways.EXPECT().FindByID(mock.Anything, ownGateway).
		Return(&gatewaydomain.Gateway{ID: ownGateway, Metadata: gatewaydomain.WithTenantID(nil, "acme")}, nil)
	gateways.EXPECT().FindByID(mock.Anything, foreignGateway).
		Return(&gatewaydomain.Gateway{ID: foreignGateway, Metadata: gatewaydomain.WithTenantID(nil, "globex")}, nil)

	lister := fakeConnectionLister{byScope: map[string][]configsyncconn.Connection{
		ownGateway.String():     {{Scope: ownGateway.String(), InstanceID: "dp-acme"}},
		foreignGateway.String(): {{Scope: foreignGateway.String(), InstanceID: "dp-globex"}},
	}}

	app := fiber.New()
	require.NoError(t, router.NewAdminRouter(router.AdminRouterDeps{
		MiddlewareTransport:       middleware.NewTransport(),
		AdminAuth:                 middleware.NewAdminAuthMiddleware(nil, jwt.NewJwtManager(&config.ServerConfig{SecretKey: secret}), nil, false),
		AdminAuthz:                middleware.NewAdminAuthzMiddleware(nil, gateways),
		ListConfigSyncConnections: configsynchttp.NewListConnectionsHandler(lister),
	}).BuildRoutes(app))

	get := func(bearer, target string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+bearer)
		res, err := app.Test(req)
		require.NoError(t, err)
		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		return res.StatusCode, string(raw)
	}

	tenantToken := signConsoleToken(t, secret, "acme")
	platformToken := signConsoleToken(t, secret, "")

	status, body := get(tenantToken, "/v1/config-sync/connections?scope="+ownGateway.String())
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "dp-acme")

	status, body = get(tenantToken, "/v1/config-sync/connections?scope="+foreignGateway.String())
	require.Equal(t, http.StatusNotFound, status, body)
	assert.NotContains(t, body, "dp-globex")

	status, body = get(tenantToken, "/v1/config-sync/connections")
	require.Equal(t, http.StatusBadRequest, status, body)

	status, body = get(platformToken, "/v1/config-sync/connections")
	require.Equal(t, http.StatusOK, status, body)
}

type fakeTraceFinder struct {
	evt *events.Event
}

func (f fakeTraceFinder) Find(_ context.Context, _ string) (*events.Event, error) {
	return f.evt, nil
}

// TestAdminRouterScopesPlaygroundTracesToCallerTenant is a regression test for
// the full route (auth + RequireInteractiveIdentity + handler): a tenant
// caller may only read a trace stamped with its own tenant, while a platform
// caller may read any trace.
func TestAdminRouterScopesPlaygroundTracesToCallerTenant(t *testing.T) {
	t.Parallel()
	const secret = "secret"
	finder := fakeTraceFinder{evt: &events.Event{TraceID: "trace-1", GatewayID: "gw-acme", TenantID: "acme"}}

	app := fiber.New()
	require.NoError(t, router.NewAdminRouter(router.AdminRouterDeps{
		MiddlewareTransport: middleware.NewTransport(),
		AdminAuth:           middleware.NewAdminAuthMiddleware(nil, jwt.NewJwtManager(&config.ServerConfig{SecretKey: secret}), nil, false),
		AdminAuthz:          middleware.NewAdminAuthzMiddleware(nil, nil),
		GetTrace:            playgroundhttp.NewGetTraceHandler(finder),
	}).BuildRoutes(app))

	get := func(bearer string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/v1/playground/traces/trace-1", nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer "+bearer)
		res, err := app.Test(req)
		require.NoError(t, err)
		raw, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
		return res.StatusCode, string(raw)
	}

	status, body := get(signConsoleToken(t, secret, "acme"))
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "trace-1")

	status, body = get(signConsoleToken(t, secret, "globex"))
	require.Equal(t, http.StatusNotFound, status, body)

	status, body = get(signConsoleToken(t, secret, ""))
	require.Equal(t, http.StatusOK, status, body)
}
