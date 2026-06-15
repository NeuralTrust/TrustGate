package middleware_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/api/resolver"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// playgroundMiddlewareSecret signs playground tokens in middleware-level tests.
const playgroundMiddlewareSecret = "playground-middleware-secret"

func mintPlaygroundToken(t *testing.T, consumerSlug string) string {
	t.Helper()
	claims := &jwt.Claims{
		UserID:       "admin-user",
		Purpose:      jwt.PurposePlayground,
		ConsumerSlug: consumerSlug,
		RegisteredClaims: golangjwt.RegisteredClaims{
			ExpiresAt: golangjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}
	token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claims).
		SignedString([]byte(playgroundMiddlewareSecret))
	require.NoError(t, err)
	return token
}

type fakeGatewayResolver struct {
	gateway *gatewaydomain.Gateway
	err     error
}

func (r fakeGatewayResolver) Resolve(_ *fiber.Ctx) (*gatewaydomain.Gateway, error) {
	return r.gateway, r.err
}

type fakeDataFinder struct {
	data *appconsumer.Data
	err  error
}

func (f fakeDataFinder) FindByGateway(_ context.Context, _ ids.GatewayID) (*appconsumer.Data, error) {
	return f.data, f.err
}

type fakeRoleResolver struct {
	roleIDs []ids.RoleID
	err     error
}

func (r fakeRoleResolver) ResolveIDPRoles(_ context.Context, _ []*roledomain.Role, _ map[string]any) ([]ids.RoleID, error) {
	return r.roleIDs, r.err
}

type fakeOAuth2Verifier struct {
	claims *appauth.VerifiedClaims
	err    error
}

func (v fakeOAuth2Verifier) Verify(_ context.Context, _ string, _ authdomain.OAuth2Config) (*appauth.VerifiedClaims, error) {
	return v.claims, v.err
}

type fakeIDPVerifier struct {
	hints  appauth.TokenHints
	claims *appauth.VerifiedClaims
	err    error
}

func (v fakeIDPVerifier) Peek(_ string) (appauth.TokenHints, error) {
	return v.hints, nil
}

func (v fakeIDPVerifier) Verify(_ context.Context, _ string, _ authdomain.IDPConfig) (*appauth.VerifiedClaims, error) {
	if v.err != nil {
		return nil, v.err
	}
	return v.claims, nil
}

func TestAuthMiddleware_APIKeyInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeIDPVerifier{}, nil)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderAPIKey, rawKey)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_APIKeyValidElsewhereForbidden(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	otherRawKey := "ag_other"
	otherAuthID := ids.New[ids.AuthKind]()
	otherRC := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gw.ID,
			Slug:        "other123",
			RoutingMode: consumerdomain.RoutingModeInline,
			Active:      true,
			AuthIDs:     []ids.AuthID{otherAuthID},
		},
		Auths: []*authdomain.Auth{{
			ID:        otherAuthID,
			GatewayID: gw.ID,
			Type:      authdomain.TypeAPIKey,
			Enabled:   true,
			KeyHash:   authdomain.HashAPIKey(otherRawKey),
		}},
	}
	data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc, otherRC})
	app := newAuthTestApp(t, gw, data, fakeOAuth2Verifier{}, fakeIDPVerifier{}, nil)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderAPIKey, otherRawKey)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestAuthMiddleware_APIKeyUnknownUnauthorized(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeIDPVerifier{}, nil)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderAPIKey, "ag_unknown")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAuthMiddleware_PlaygroundTokenInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeIDPVerifier{}, nil)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderPlaygroundToken, mintPlaygroundToken(t, rc.Consumer.Slug))
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_PlaygroundTokenRoleBasedSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, _ := roleBasedConsumerWithIDP(t)
	failingRoles := fakeRoleResolver{err: fmt.Errorf("idp roles must not be resolved for playground tokens")}
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeIDPVerifier{}, failingRoles)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderPlaygroundToken, mintPlaygroundToken(t, rc.Consumer.Slug))
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_PlaygroundTokenWrongConsumerForbidden(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeIDPVerifier{}, nil)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderPlaygroundToken, mintPlaygroundToken(t, "other-consumer"))
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestAuthMiddleware_OAuthInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc := inlineConsumerWithOAuth(t)
	oauthVerifier := fakeOAuth2Verifier{claims: &appauth.VerifiedClaims{
		Subject: "user-1",
		Claims:  map[string]any{"sub": "user-1"},
		Scopes:  []string{"chat"},
	}}
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), oauthVerifier, fakeIDPVerifier{}, nil)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer token")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_IDPRoleBasedSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, roleID := roleBasedConsumerWithIDP(t)
	idpVerifier := matchingIDPVerifier()
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, idpVerifier, fakeRoleResolver{roleIDs: []ids.RoleID{roleID}})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer token")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_OAuthCannotAuthorizeRoleBasedConsumer(t *testing.T) {
	t.Parallel()
	gw, rc := roleBasedConsumerWithOAuth(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeIDPVerifier{}, nil)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer token")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestAuthMiddleware_IDPRoleBasedNoRoleForbidden(t *testing.T) {
	t.Parallel()
	gw, rc, _ := roleBasedConsumerWithIDP(t)
	idpVerifier := matchingIDPVerifier()
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, idpVerifier, fakeRoleResolver{roleIDs: nil})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer token")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestAuthMiddleware_ErrorMatrix(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc})

	tests := []struct {
		name           string
		gatewayErr     error
		data           *appconsumer.Data
		headers        map[string]string
		wantStatusCode int
		wantError      string
	}{
		{
			name:           "malformed host config returns 400",
			gatewayErr:     fmt.Errorf("%w: malformed host", appauth.ErrInvalidAuthRequest),
			headers:        map[string]string{resolver.HeaderAPIKey: "ag_any"},
			wantStatusCode: fiber.StatusBadRequest,
			wantError:      "invalid_auth_request",
		},
		{
			name:           "invalid proxy auth config returns 400",
			gatewayErr:     fmt.Errorf("%w: malformed auth config", commonerrors.ErrInvalidConfig),
			headers:        map[string]string{resolver.HeaderAPIKey: "ag_any"},
			wantStatusCode: fiber.StatusBadRequest,
			wantError:      "invalid_auth_request",
		},
		{
			name:           "missing credential returns 401",
			data:           data,
			wantStatusCode: fiber.StatusUnauthorized,
			wantError:      "unauthenticated",
		},
		{
			name:           "path miss returns 404",
			data:           appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{}),
			headers:        map[string]string{resolver.HeaderAPIKey: "ag_any"},
			wantStatusCode: fiber.StatusNotFound,
			wantError:      "not_found",
		},
		{
			name:           "unexpected gateway resolution failure returns 500",
			gatewayErr:     fmt.Errorf("database is down"),
			headers:        map[string]string{resolver.HeaderAPIKey: "ag_any"},
			wantStatusCode: fiber.StatusInternalServerError,
			wantError:      "internal_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newAuthTestAppWithResolver(
				t,
				fakeGatewayResolver{gateway: gw, err: tt.gatewayErr},
				tt.data,
				fakeOAuth2Verifier{},
				fakeIDPVerifier{},
				nil,
			)
			req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
			req.Host = "acme.gw.neuraltrust.ai"
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			resp, err := app.Test(req)
			require.NoError(t, err)
			require.Equal(t, tt.wantStatusCode, resp.StatusCode)
			require.Equal(t, tt.wantError, decodeAuthErrorBody(t, resp).Error)
		})
	}
}

func TestAuthMiddleware_RejectsHeaderOnlyGatewayIdentity(t *testing.T) {
	t.Parallel()
	app := newAuthTestAppWithResolver(
		t,
		fakeGatewayResolver{err: fmt.Errorf("%w: host is required", appauth.ErrInvalidAuthRequest)},
		nil,
		fakeOAuth2Verifier{},
		fakeIDPVerifier{},
		nil,
	)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Header.Set("X-AG-"+"Gateway-ID", ids.New[ids.GatewayKind]().String())
	req.Header.Set(resolver.HeaderAPIKey, "ag_any")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	require.Equal(t, "invalid_auth_request", decodeAuthErrorBody(t, resp).Error)
}

func newAuthTestApp(
	t *testing.T,
	gw *gatewaydomain.Gateway,
	data *appconsumer.Data,
	oauthVerifier fakeOAuth2Verifier,
	idpVerifier fakeIDPVerifier,
	roleResolver middlewareRoleResolver,
) *fiber.App {
	t.Helper()
	return newAuthTestAppWithResolver(t, fakeGatewayResolver{gateway: gw}, data, oauthVerifier, idpVerifier, roleResolver)
}

type middlewareRoleResolver interface {
	ResolveIDPRoles(context.Context, []*roledomain.Role, map[string]any) ([]ids.RoleID, error)
}

func newAuthTestAppWithResolver(
	t *testing.T,
	gatewayResolver resolver.GatewayResolver,
	data *appconsumer.Data,
	oauthVerifier fakeOAuth2Verifier,
	idpVerifier fakeIDPVerifier,
	roleResolver middlewareRoleResolver,
) *fiber.App {
	t.Helper()
	if roleResolver == nil {
		roleResolver = fakeRoleResolver{}
	}
	playground := resolver.NewPlaygroundIdentityResolver(
		jwt.NewJwtManager(&config.ServerConfig{SecretKey: playgroundMiddlewareSecret}),
	)
	apiKey := resolver.NewAPIKeyIdentityResolver()
	oauth2 := resolver.NewOAuth2IdentityResolver(oauthVerifier)
	idp := resolver.NewIDPIdentityResolver(appauth.NewIDPFinder(idpVerifier), idpVerifier)
	authMiddleware := middleware.NewAuthMiddleware(
		resolver.NewIdentityResolver(playground, apiKey, oauth2, idp),
		fakeDataFinder{data: data},
		gatewayResolver,
		roleResolver,
		slog.Default(),
	)
	app := fiber.New()
	app.Post("/*", authMiddleware.Middleware(), func(c *fiber.Ctx) error {
		authCtx, ok := appauth.AuthContextFromContext(c.UserContext())
		require.True(t, ok)
		require.Equal(t, data.GatewayID, authCtx.GatewayID)
		_, ok = appconsumer.ConsumerFromContext(c.UserContext())
		require.True(t, ok)
		return c.SendStatus(fiber.StatusOK)
	})
	return app
}

func inlineConsumerWithAPIKey(t *testing.T) (*gatewaydomain.Gateway, appconsumer.RoutableConsumer, string) {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	authID := ids.New[ids.AuthKind]()
	rawKey := "ag_secret"
	rc := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gw.ID,
			Slug:        "cons1234",
			RoutingMode: consumerdomain.RoutingModeInline,
			Active:      true,
			AuthIDs:     []ids.AuthID{authID},
		},
		Auths: []*authdomain.Auth{{
			ID:        authID,
			GatewayID: gw.ID,
			Type:      authdomain.TypeAPIKey,
			Enabled:   true,
			KeyHash:   authdomain.HashAPIKey(rawKey),
		}},
	}
	return gw, rc, rawKey
}

func inlineConsumerWithOAuth(t *testing.T) (*gatewaydomain.Gateway, appconsumer.RoutableConsumer) {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	authID := ids.New[ids.AuthKind]()
	rc := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gw.ID,
			Slug:        "cons1234",
			RoutingMode: consumerdomain.RoutingModeInline,
			Active:      true,
			AuthIDs:     []ids.AuthID{authID},
		},
		Auths: []*authdomain.Auth{{
			ID:        authID,
			GatewayID: gw.ID,
			Type:      authdomain.TypeOAuth2,
			Enabled:   true,
			Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"gateway"},
				JWKSURL:   "https://issuer.example.com/jwks",
			}},
		}},
	}
	return gw, rc
}

func roleBasedConsumerWithIDP(t *testing.T) (*gatewaydomain.Gateway, appconsumer.RoutableConsumer, ids.RoleID) {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	authID := ids.New[ids.AuthKind]()
	roleID := ids.New[ids.RoleKind]()
	rc := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gw.ID,
			Slug:        "cons1234",
			RoutingMode: consumerdomain.RoutingModeRoleBased,
			Active:      true,
			AuthIDs:     []ids.AuthID{authID},
			RoleIDs:     []ids.RoleID{roleID},
		},
		Auths: []*authdomain.Auth{{
			ID:        authID,
			GatewayID: gw.ID,
			Type:      authdomain.TypeIDP,
			Enabled:   true,
			Config: authdomain.Config{IDP: &authdomain.IDPConfig{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"gateway"},
				JWKSURL:   "https://issuer.example.com/jwks",
			}},
		}},
	}
	return gw, rc, roleID
}

func roleBasedConsumerWithOAuth(t *testing.T) (*gatewaydomain.Gateway, appconsumer.RoutableConsumer) {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	authID := ids.New[ids.AuthKind]()
	roleID := ids.New[ids.RoleKind]()
	rc := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gw.ID,
			Slug:        "cons1234",
			RoutingMode: consumerdomain.RoutingModeRoleBased,
			Active:      true,
			AuthIDs:     []ids.AuthID{authID},
			RoleIDs:     []ids.RoleID{roleID},
		},
		Auths: []*authdomain.Auth{{
			ID:        authID,
			GatewayID: gw.ID,
			Type:      authdomain.TypeOAuth2,
			Enabled:   true,
			Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"gateway"},
				JWKSURL:   "https://issuer.example.com/jwks",
			}},
		}},
	}
	return gw, rc
}

func matchingIDPVerifier() fakeIDPVerifier {
	return fakeIDPVerifier{
		hints: appauth.TokenHints{Issuer: "https://issuer.example.com", Audiences: []string{"gateway"}},
		claims: &appauth.VerifiedClaims{
			Subject: "user-1",
			Claims:  map[string]any{"sub": "user-1", "groups": []any{"support"}},
			Scopes:  []string{"chat"},
		},
	}
}

func decodeAuthErrorBody(t *testing.T, resp *http.Response) helpers.ErrorBody {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return decodeErrorBytes(t, body)
}

func decodeErrorBytes(t *testing.T, body []byte) helpers.ErrorBody {
	t.Helper()
	var eb helpers.ErrorBody
	require.NoError(t, json.NewDecoder(strings.NewReader(string(body))).Decode(&eb))
	return eb
}
