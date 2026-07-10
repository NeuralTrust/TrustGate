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

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
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

func (r fakeRoleResolver) ResolveOIDCRoles(_ context.Context, _ []*roledomain.Role, _ map[string]any) ([]ids.RoleID, error) {
	return r.roleIDs, r.err
}

type fakeOAuth2Verifier struct {
	claims *appauth.VerifiedClaims
	err    error
}

func (v fakeOAuth2Verifier) Verify(_ context.Context, _ string, _ authdomain.OAuth2Config) (*appauth.VerifiedClaims, error) {
	return v.claims, v.err
}

type fakeOIDCVerifier struct {
	hints  appauth.TokenHints
	claims *appauth.VerifiedClaims
	err    error
}

func (v fakeOIDCVerifier) Peek(_ string) (appauth.TokenHints, error) {
	return v.hints, nil
}

func (v fakeOIDCVerifier) Verify(_ context.Context, _ string, _ authdomain.OIDCConfig) (*appauth.VerifiedClaims, error) {
	if v.err != nil {
		return nil, v.err
	}
	return v.claims, nil
}

func TestAuthMiddleware_APIKeyInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{}, nil)

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
	app := newAuthTestApp(t, gw, data, fakeOAuth2Verifier{}, fakeOIDCVerifier{}, nil)

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{}, nil)

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{}, nil)

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{}, failingRoles)

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{}, nil)

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), oauthVerifier, fakeOIDCVerifier{}, nil)

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
	oidcVerifier := matchingOIDCVerifier()
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, oidcVerifier, fakeRoleResolver{roleIDs: []ids.RoleID{roleID}})

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{}, nil)

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
	oidcVerifier := matchingOIDCVerifier()
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, oidcVerifier, fakeRoleResolver{roleIDs: nil})

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
				fakeOIDCVerifier{},
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
		fakeOIDCVerifier{},
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
	oidcVerifier fakeOIDCVerifier,
	roleResolver middlewareRoleResolver,
) *fiber.App {
	t.Helper()
	return newAuthTestAppWithResolver(t, fakeGatewayResolver{gateway: gw}, data, oauthVerifier, oidcVerifier, roleResolver)
}

type middlewareRoleResolver interface {
	ResolveOIDCRoles(context.Context, []*roledomain.Role, map[string]any) ([]ids.RoleID, error)
}

func newAuthTestAppWithResolver(
	t *testing.T,
	gatewayResolver resolver.GatewayResolver,
	data *appconsumer.Data,
	oauthVerifier fakeOAuth2Verifier,
	oidcVerifier fakeOIDCVerifier,
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
	idp := resolver.NewOIDCIdentityResolver(appauth.NewOIDCFinder(oidcVerifier), oidcVerifier)
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
			Type:      authdomain.TypeOIDC,
			Enabled:   true,
			Config: authdomain.Config{OIDC: &authdomain.OIDCConfig{
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

func matchingOIDCVerifier() fakeOIDCVerifier {
	return fakeOIDCVerifier{
		hints: appauth.TokenHints{Issuer: "https://issuer.example.com", Audiences: []string{"gateway"}},
		claims: &appauth.VerifiedClaims{
			Subject: "user-1",
			Claims:  map[string]any{"sub": "user-1", "groups": []any{"support"}},
			Scopes:  []string{"chat"},
		},
	}
}

func decodeAuthErrorBody(t *testing.T, resp *http.Response) httpio.ErrorBody {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return decodeErrorBytes(t, body)
}

func decodeErrorBytes(t *testing.T, body []byte) httpio.ErrorBody {
	t.Helper()
	var eb httpio.ErrorBody
	require.NoError(t, json.NewDecoder(strings.NewReader(string(body))).Decode(&eb))
	return eb
}
