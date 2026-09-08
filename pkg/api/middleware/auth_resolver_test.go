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

func (v fakeOIDCVerifier) Verify(_ context.Context, _ string, _ authdomain.OAuth2Config) (*appauth.VerifiedClaims, error) {
	if v.err != nil {
		return nil, v.err
	}
	return v.claims, nil
}

func TestAuthMiddleware_APIKeyInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderAPIKey, rawKey)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_APIKeyBearerInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+rawKey)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_APIKeyCompatHeaderInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderAPIKeyCompat, rawKey)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_APIKeyBearerUnknownUnauthorized(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer ag_unknown")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestAuthMiddleware_APIKeyBearerValidElsewhereForbidden(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	otherRawKey := "ag_other"
	otherAuthID := ids.New[ids.AuthKind]()
	otherRC := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gw.ID,
			Slug:      "other123",
			Active:    true,
			AuthIDs:   []ids.AuthID{otherAuthID},
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
	app := newAuthTestApp(t, gw, data, fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+otherRawKey)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestAuthMiddleware_APIKeyValidElsewhereForbidden(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	otherRawKey := "ag_other"
	otherAuthID := ids.New[ids.AuthKind]()
	otherRC := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gw.ID,
			Slug:      "other123",
			Active:    true,
			AuthIDs:   []ids.AuthID{otherAuthID},
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
	app := newAuthTestApp(t, gw, data, fakeOAuth2Verifier{}, fakeOIDCVerifier{})

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

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
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), oauthVerifier, fakeOIDCVerifier{})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer token")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// A consumer whose provider is still typed with the deprecated alias
// authenticates through the one bearer path: the finder matches it on the
// token's hints and the verifier is the same one every provider now uses.
func TestAuthMiddleware_AliasedIdPInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc := inlineConsumerWithOIDC(t)
	hints := matchingOIDCVerifier()
	verifier := fakeOAuth2Verifier{claims: hints.claims}
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), verifier, hints)

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(fiber.HeaderAuthorization, "Bearer token")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
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
) *fiber.App {
	t.Helper()
	return newAuthTestAppWithResolver(t, fakeGatewayResolver{gateway: gw}, data, oauthVerifier, oidcVerifier)
}

func newAuthTestAppWithResolver(
	t *testing.T,
	gatewayResolver resolver.GatewayResolver,
	data *appconsumer.Data,
	oauthVerifier fakeOAuth2Verifier,
	oidcVerifier fakeOIDCVerifier,
) *fiber.App {
	t.Helper()
	playground := resolver.NewPlaygroundIdentityResolver(
		jwt.NewJwtManager(&config.ServerConfig{SecretKey: playgroundMiddlewareSecret}),
	)
	apiKey := resolver.NewAPIKeyIdentityResolver()
	oauth2 := resolver.NewOAuth2IdentityResolver(
		appauth.NewIdentityProviderFinder(oidcVerifier),
		oauthVerifier,
		slog.Default(),
	)
	authMiddleware := middleware.NewAuthMiddleware(
		resolver.NewIdentityResolver(playground, apiKey, oauth2),
		fakeDataFinder{data: data},
		gatewayResolver,
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
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gw.ID,
			Slug:      "cons1234",
			Active:    true,
			AuthIDs:   []ids.AuthID{authID},
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
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gw.ID,
			Slug:      "cons1234",
			Active:    true,
			AuthIDs:   []ids.AuthID{authID},
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

func inlineConsumerWithOIDC(t *testing.T) (*gatewaydomain.Gateway, appconsumer.RoutableConsumer) {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	authID := ids.New[ids.AuthKind]()
	rc := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gw.ID,
			Slug:      "cons1234",
			Active:    true,
			AuthIDs:   []ids.AuthID{authID},
		},
		Auths: []*authdomain.Auth{{
			ID:        authID,
			GatewayID: gw.ID,
			Type:      authdomain.TypeOIDC,
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

// TestAuthMiddleware_AuthBindingRestrictsClients: a consumer bound to specific
// client ids admits a bearer token only when the shared IdP issued it to one of
// them; a token for another application of the same tenant is forbidden even
// though it verifies against the same auth.
func TestAuthMiddleware_AuthBindingRestrictsClients(t *testing.T) {
	t.Parallel()
	gw, rc := inlineConsumerWithOAuth(t)
	rc.Consumer.AuthBinding = consumerdomain.AuthBinding{AllowedClientIDs: []string{"app-a"}}
	data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc})

	cases := map[string]struct {
		claims map[string]any
		want   int
	}{
		"token issued to an allowed client":  {map[string]any{"sub": "user-1", "azp": "app-a"}, fiber.StatusOK},
		"token issued to another client":     {map[string]any{"sub": "user-1", "azp": "app-b"}, fiber.StatusForbidden},
		"token without a client claim":       {map[string]any{"sub": "user-1"}, fiber.StatusForbidden},
		"client_id claim names the consumer": {map[string]any{"sub": "user-1", "client_id": "app-a"}, fiber.StatusOK},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			verifier := fakeOAuth2Verifier{claims: &appauth.VerifiedClaims{Subject: "user-1", Claims: tc.claims}}
			app := newAuthTestApp(t, gw, data, verifier, fakeOIDCVerifier{})
			req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
			req.Host = "acme.gw.neuraltrust.ai"
			req.Header.Set(fiber.HeaderAuthorization, "Bearer token")
			resp, err := app.Test(req)
			require.NoError(t, err)
			require.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

// Before the two identity-provider types were unified, a consumer carrying
// both shapes had its aliased provider silently ignored: bearer resolution
// branched on the auth type, took the oauth2 branch whenever an oauth2 auth
// was attached, and that branch skipped every auth whose type was not exactly
// oauth2. A token issued by the aliased provider got a 401 from a consumer it
// was legitimately attached to. Selection now comes from the token's own
// issuer and audience, so both providers stay reachable.
func TestAuthMiddleware_AliasedAndNativeIdPsBothResolve(t *testing.T) {
	t.Parallel()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	aliasedID := ids.New[ids.AuthKind]()
	nativeID := ids.New[ids.AuthKind]()
	rc := appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gw.ID,
			Slug:      "cons1234",
			Active:    true,
			AuthIDs:   []ids.AuthID{aliasedID, nativeID},
		},
		Auths: []*authdomain.Auth{
			{
				ID: aliasedID, GatewayID: gw.ID, Type: authdomain.TypeOIDC, Enabled: true,
				Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
					Issuer:    "https://aliased.example.com",
					Audiences: []string{"gateway"},
					JWKSURL:   "https://aliased.example.com/jwks",
				}},
			},
			{
				ID: nativeID, GatewayID: gw.ID, Type: authdomain.TypeOAuth2, Enabled: true,
				Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
					Issuer:    "https://native.example.com",
					Audiences: []string{"gateway"},
					JWKSURL:   "https://native.example.com/jwks",
				}},
			},
		},
	}

	for _, tc := range []struct {
		name   string
		issuer string
	}{
		{"token from the aliased provider", "https://aliased.example.com"},
		{"token from the native provider", "https://native.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hints := fakeOIDCVerifier{hints: appauth.TokenHints{Issuer: tc.issuer, Audiences: []string{"gateway"}}}
			verifier := fakeOAuth2Verifier{claims: &appauth.VerifiedClaims{
				Subject: "user-1",
				Claims:  map[string]any{"sub": "user-1"},
			}}
			app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), verifier, hints)

			req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
			req.Host = "acme.gw.neuraltrust.ai"
			req.Header.Set(fiber.HeaderAuthorization, "Bearer token")
			resp, err := app.Test(req)
			require.NoError(t, err)
			require.Equal(t, fiber.StatusOK, resp.StatusCode)
		})
	}
}
