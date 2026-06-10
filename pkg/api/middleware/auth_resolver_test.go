package middleware_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type fakeAPIKeyFinder struct {
	auth *domain.Auth
	err  error
}

func (f fakeAPIKeyFinder) FindByAPIKey(_ context.Context, _ string) (*domain.Auth, error) {
	return f.auth, f.err
}

var _ appauth.APIKeyFinder = fakeAPIKeyFinder{}

func runResolve(t *testing.T, finder appauth.APIKeyFinder, headers map[string]string) (middleware.Identity, error) {
	t.Helper()
	resolver := middleware.NewAPIKeyIdentityResolver(finder)
	var (
		gotIdentity middleware.Identity
		gotErr      error
	)
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		gotIdentity, gotErr = resolver.Resolve(c)
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	_, err := app.Test(req)
	require.NoError(t, err)
	return gotIdentity, gotErr
}

func TestAPIKeyResolver_MissingHeader_Unauthenticated(t *testing.T) {
	_, err := runResolve(t, fakeAPIKeyFinder{}, nil)
	require.ErrorIs(t, err, middleware.ErrUnauthenticated)
}

func TestAuthMiddleware_MissingHeader_ReturnsJSONUnauthorized(t *testing.T) {
	resolver := middleware.NewAPIKeyIdentityResolver(fakeAPIKeyFinder{})
	mw := middleware.NewAuthMiddleware(resolver, nil, nil)

	app := fiber.New()
	app.Get("/", mw.Middleware(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	require.True(t, strings.HasPrefix(resp.Header.Get(fiber.HeaderContentType), fiber.MIMEApplicationJSON))
	require.Equal(t, helpers.ErrorBody{
		Error:   "unauthenticated",
		Message: "unauthenticated",
	}, decodeErrorBody(t, resp))
}

func TestAPIKeyResolver_ValidKey_ResolvesIdentity(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()
	finder := fakeAPIKeyFinder{auth: &domain.Auth{ID: authID, GatewayID: gwID, Type: domain.TypeAPIKey, Enabled: true}}

	identity, err := runResolve(t, finder, map[string]string{middleware.HeaderAPIKey: "ag_some-key"})
	require.NoError(t, err)
	require.Equal(t, gwID, identity.GatewayID)
	require.Equal(t, authID, identity.AuthID)
}

func TestAPIKeyResolver_DisabledKey_Unauthenticated(t *testing.T) {
	finder := fakeAPIKeyFinder{auth: &domain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: ids.New[ids.GatewayKind](), Type: domain.TypeAPIKey, Enabled: false}}
	_, err := runResolve(t, finder, map[string]string{middleware.HeaderAPIKey: "ag_disabled"})
	require.ErrorIs(t, err, middleware.ErrUnauthenticated)
}

func TestAPIKeyResolver_LookupError_Unauthenticated(t *testing.T) {
	finder := fakeAPIKeyFinder{err: domain.ErrNotFound}
	_, err := runResolve(t, finder, map[string]string{middleware.HeaderAPIKey: "ag_missing"})
	require.ErrorIs(t, err, middleware.ErrUnauthenticated)
}

func TestAPIKeyResolver_WrongType_Unauthenticated(t *testing.T) {
	finder := fakeAPIKeyFinder{auth: &domain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: ids.New[ids.GatewayKind](), Type: domain.TypeOAuth2, Enabled: true}}
	_, err := runResolve(t, finder, map[string]string{middleware.HeaderAPIKey: "ag_oauth"})
	require.ErrorIs(t, err, middleware.ErrUnauthenticated)
}
