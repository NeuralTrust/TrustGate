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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
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

func TestAuthMiddleware_APIKeyGoogleHeaderInlineSuccess(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1beta/models/gemini-2.5-pro:generateContent", nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderAPIKeyGoogle, rawKey)
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

var authTestNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func otherConsumerWithKey(gw *gatewaydomain.Gateway, rawKey string, expiresAt *time.Time) appconsumer.RoutableConsumer {
	authID := ids.New[ids.AuthKind]()
	return appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Slug: "other123", Active: true, AuthIDs: []ids.AuthID{authID}},
		Auths: []*authdomain.Auth{{
			ID: authID, GatewayID: gw.ID, Type: authdomain.TypeAPIKey, Enabled: true,
			KeyHash: authdomain.HashAPIKey(rawKey), ExpiresAt: expiresAt,
		}},
	}
}

func authTestClock() time.Time { return authTestNow }

func TestAuthMiddleware_APIKeyExpiryDecidesBetween401And403(t *testing.T) {
	t.Parallel()
	past := authTestNow.Add(-time.Second)
	future := authTestNow.Add(time.Hour)
	cases := map[string]struct {
		ownExpiry   *time.Time
		otherExpiry *time.Time
		presentOwn  bool
		want        int
	}{
		"expired key on its own consumer":        {ownExpiry: &past, presentOwn: true, want: fiber.StatusUnauthorized},
		"key expiring now on its own consumer":   {ownExpiry: &authTestNow, presentOwn: true, want: fiber.StatusUnauthorized},
		"future expiry on its own consumer":      {ownExpiry: &future, presentOwn: true, want: fiber.StatusOK},
		"expired key of another consumer":        {otherExpiry: &past, want: fiber.StatusUnauthorized},
		"key of another consumer expiring now":   {otherExpiry: &authTestNow, want: fiber.StatusUnauthorized},
		"valid key of another consumer":          {otherExpiry: &future, want: fiber.StatusForbidden},
		"never-expiring key of another consumer": {want: fiber.StatusForbidden},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gw, rc, ownKey := inlineConsumerWithAPIKey(t)
			rc.Auths[0].ExpiresAt = tc.ownExpiry
			otherKey := "ag_other"
			data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc, otherConsumerWithKey(gw, otherKey, tc.otherExpiry)})
			app := newAuthTestApp(t, gw, data, fakeOAuth2Verifier{}, fakeOIDCVerifier{})

			key := otherKey
			if tc.presentOwn {
				key = ownKey
			}
			req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
			req.Host = "acme.gw.neuraltrust.ai"
			req.Header.Set(resolver.HeaderAPIKey, key)
			resp, err := app.Test(req)
			require.NoError(t, err)
			require.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

func personalConsumerWithKey(gw *gatewaydomain.Gateway, rawKey string) appconsumer.RoutableConsumer {
	ownedID := ids.New[ids.AuthKind]()
	return appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Slug: "pslug001", Active: true,
			Type: consumerdomain.TypeLLM, Audience: consumerdomain.AudiencePersonal, AuthIDs: []ids.AuthID{ownedID},
			AuthLinks: map[ids.AuthID]consumerdomain.AuthLink{ownedID: {Level: consumerdomain.GrantLevelUser, Priority: 1, GrantedAt: authTestNow}},
		},
		Auths: []*authdomain.Auth{{
			ID: ownedID, GatewayID: gw.ID, Type: authdomain.TypeAPIKey, Enabled: true,
			KeyHash: authdomain.HashAPIKey(rawKey), OwnerID: "alice",
		}},
	}
}

func callAuthApp(t *testing.T, app *fiber.App, path, key string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, path, nil)
	req.Host = "acme.gw.neuraltrust.ai"
	req.Header.Set(resolver.HeaderAPIKey, key)
	resp, err := app.Test(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func TestAuthMiddleware_PersonalKeysStayOffSlugRoutes(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	ownedKey, otherKey := "ag_alice", "ag_other"
	data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc, personalConsumerWithKey(gw, ownedKey), otherConsumerWithKey(gw, otherKey, nil)})
	app := newAuthTestApp(t, gw, data, fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	status, ownedBody := callAuthApp(t, app, "/cons1234/v1/chat/completions", ownedKey)
	require.Equal(t, fiber.StatusUnauthorized, status, "a personal key on an application slug")
	_, unknownKeyBody := callAuthApp(t, app, "/cons1234/v1/chat/completions", "ag_random")
	require.Equal(t, unknownKeyBody, ownedBody)
	status, _ = callAuthApp(t, app, "/cons1234/v1/chat/completions", otherKey)
	require.Equal(t, fiber.StatusForbidden, status, "an application key of another application consumer")
	status, personalBody := callAuthApp(t, app, "/pslug001/v1/chat/completions", ownedKey)
	require.Equal(t, fiber.StatusNotFound, status, "a personal consumer by slug")
	_, unknownSlugBody := callAuthApp(t, app, "/zzzzzzzz/v1/chat/completions", ownedKey)
	require.Equal(t, unknownSlugBody, personalBody)

	oauthGW, oauthRC := inlineConsumerWithOAuth(t)
	oauthData := appconsumer.NewData(oauthGW.ID, []appconsumer.RoutableConsumer{oauthRC, personalConsumerWithKey(oauthGW, ownedKey)})
	oauthApp := newAuthTestApp(t, oauthGW, oauthData, fakeOAuth2Verifier{}, fakeOIDCVerifier{})
	ownedStatus, ownedOnOAuth := callAuthApp(t, oauthApp, "/cons1234/v1/chat/completions", ownedKey)
	unknownStatus, unknownOnOAuth := callAuthApp(t, oauthApp, "/cons1234/v1/chat/completions", "ag_random")
	require.Equal(t, unknownStatus, ownedStatus, "a personal key on an OAuth-only application consumer")
	require.Equal(t, unknownOnOAuth, ownedOnOAuth)
}

func TestAuthMiddleware_NilClockFallsBackToTheWallClock(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	otherKey := "ag_other"
	expired := time.Now().UTC().Add(-time.Hour)
	authMiddleware := middleware.NewAuthMiddleware(
		resolver.NewIdentityResolver(nil, resolver.NewAPIKeyIdentityResolver(nil), nil, nil),
		fakeDataFinder{data: appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc, otherConsumerWithKey(gw, otherKey, &expired)})},
		fakeGatewayResolver{gateway: gw},
		nil,
		slog.Default(),
		nil,
	)
	app := fiber.New()
	app.Post("/*", authMiddleware.Middleware(), func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
	req.Header.Set(resolver.HeaderAPIKey, otherKey)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
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
		Method:  identity.MethodJWT,
		Issuer:  "https://issuer.example.com",
		Claims:  map[string]any{"sub": "user-1", "email": "user@example.com"},
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
		jwt.NewPlaygroundVerifier(&config.ServerConfig{SecretKey: playgroundMiddlewareSecret}, nil),
	)
	apiKey := resolver.NewAPIKeyIdentityResolver(authTestClock)
	oauth2 := resolver.NewOAuth2IdentityResolver(
		appauth.NewIdentityProviderFinder(oidcVerifier),
		oauthVerifier,
		slog.Default(),
	)
	authMiddleware := middleware.NewAuthMiddleware(
		resolver.NewIdentityResolver(playground, apiKey, oauth2, nil),
		fakeDataFinder{data: data},
		gatewayResolver,
		nil,
		slog.Default(),
		authTestClock,
	)
	app := fiber.New()
	app.Post("/*", authMiddleware.Middleware(), func(c *fiber.Ctx) error {
		authCtx, ok := appauth.AuthContextFromContext(c.UserContext())
		require.True(t, ok)
		require.Equal(t, data.GatewayID, authCtx.GatewayID)
		switch authCtx.Method {
		case appauth.MethodOAuth2:
			p := identity.PrincipalFromContext(c.UserContext())
			require.NotNil(t, p)
			require.Equal(t, authCtx.Subject, p.Subject)
			require.Same(t, oauthVerifier.claims, p)
			require.Equal(t, oauthVerifier.claims.Method, p.Method)
			require.Equal(t, oauthVerifier.claims.Email(), p.Email())
		case appauth.MethodAPIKey:
			// An API key's name is the identity it carries; the telemetry
			// contract publishes it as principal.subject/api_key.
			p := identity.PrincipalFromContext(c.UserContext())
			require.NotNil(t, p)
			require.Equal(t, "batch-runner", p.Subject)
			require.Equal(t, identity.MethodAPIKey, p.Method)
		default:
			require.Nil(t, identity.PrincipalFromContext(c.UserContext()))
		}
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
			Name:      "batch-runner",
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

const storeChatPath = "/store/v1/chat/completions"

type countingKeyFinder struct {
	keys  map[string]*authdomain.Auth
	err   error
	calls atomic.Int32
}

func (f *countingKeyFinder) FindByAPIKey(_ context.Context, rawKey string) (*authdomain.Auth, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.keys[rawKey]; ok {
		return a, nil
	}
	return nil, authdomain.ErrNotFound
}

type storeFixture struct {
	gw        *gatewaydomain.Gateway
	consumers []appconsumer.RoutableConsumer
	data      *appconsumer.Data
	dataErr   error
	finder    *countingKeyFinder
	storeKeys appconsumer.StoreKeyResolver
	appKey    string
	ownedID   ids.AuthID
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	gw, rc, appKey := inlineConsumerWithAPIKey(t)
	personal := personalConsumerWithKey(gw, "ag_alice")
	finder := &countingKeyFinder{keys: map[string]*authdomain.Auth{"ag_alice": personal.Auths[0], appKey: rc.Auths[0]}}
	return &storeFixture{
		gw: gw, consumers: []appconsumer.RoutableConsumer{rc, personal}, appKey: appKey, ownedID: personal.Auths[0].ID,
		finder: finder, storeKeys: appconsumer.NewStoreKeyResolver(finder, authTestClock),
	}
}

func (f *storeFixture) app(next fiber.Handler) *fiber.App {
	f.data = appconsumer.NewData(f.gw.ID, f.consumers)
	if next == nil {
		next = func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) }
	}
	authMiddleware := middleware.NewAuthMiddleware(
		resolver.NewIdentityResolver(nil, resolver.NewAPIKeyIdentityResolver(authTestClock), nil, nil),
		fakeDataFinder{data: f.data, err: f.dataErr},
		fakeGatewayResolver{gateway: f.gw},
		f.storeKeys,
		slog.Default(),
		authTestClock,
	)
	app := fiber.New()
	app.Post("/*", authMiddleware.Middleware(), next)
	return app
}

func callStore(t *testing.T, app *fiber.App, path, header, value string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, path, nil)
	if header != "" {
		req.Header.Set(header, value)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func TestAuthMiddleware_StoreAnswersNotFoundBeforeAnyKeyLookup(t *testing.T) {
	t.Parallel()
	cases := map[string]func(f *storeFixture){
		"no personal consumers":            func(f *storeFixture) { f.consumers = f.consumers[:1] },
		"only inactive personal consumers": func(f *storeFixture) { f.consumers[1].Consumer.Active = false },
		"hybrid gateway":                   func(f *storeFixture) { f.gw.Entitlements.DataPlane = gatewaydomain.DataPlaneHybrid },
		"hybrid gateway with a data load error": func(f *storeFixture) {
			f.gw.Entitlements.DataPlane, f.dataErr = gatewaydomain.DataPlaneHybrid, errors.New("down")
		},
		"store not wired": func(f *storeFixture) { f.storeKeys = nil },
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, unknownSlug := callStore(t, newStoreFixture(t).app(nil), "/zzzzzzzz/v1/chat/completions", "", "")
			f := newStoreFixture(t)
			arrange(f)
			app := f.app(nil)
			for _, key := range []string{"", f.appKey, "ag_alice"} {
				status, body := callStore(t, app, storeChatPath, resolver.HeaderAPIKey, key)
				require.Equal(t, fiber.StatusNotFound, status)
				require.Equal(t, unknownSlug, body)
				status, _ = callStore(t, app, "/store/v1/models", resolver.HeaderAPIKey, key)
				require.Equal(t, fiber.StatusNotFound, status)
			}
			require.Zero(t, f.finder.calls.Load())
		})
	}
}

func TestAuthMiddleware_StoreRejectsKeysItDoesNotAcceptAndLeavesOtherSlugsUnchanged(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	f.finder.keys["ag_expired"] = &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: f.gw.ID, Type: authdomain.TypeAPIKey, Enabled: true, KeyHash: authdomain.HashAPIKey("ag_expired"), OwnerID: "alice", ExpiresAt: &authTestNow}
	f.finder.keys["ag_disabled"] = &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: f.gw.ID, Type: authdomain.TypeAPIKey, KeyHash: authdomain.HashAPIKey("ag_disabled"), OwnerID: "alice"}
	f.finder.keys["ag_other_gw"] = &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: ids.New[ids.GatewayKind](), Type: authdomain.TypeAPIKey, Enabled: true, KeyHash: authdomain.HashAPIKey("ag_other_gw"), OwnerID: "alice"}
	app := f.app(nil)
	status, noKey := callStore(t, app, storeChatPath, "", "")
	require.Equal(t, fiber.StatusUnauthorized, status)
	require.Equal(t, "unauthenticated", decodeErrorBytes(t, noKey).Error)
	for _, key := range []string{"ag_unknown", "ag_expired", "ag_disabled", "ag_other_gw", f.appKey} {
		status, body := callStore(t, app, storeChatPath, resolver.HeaderAPIKey, key)
		require.Equal(t, fiber.StatusUnauthorized, status, key)
		require.Equal(t, noKey, body, key)
	}
	lookups := f.finder.calls.Load()
	status, _ = callStore(t, app, "/cons1234/v1/chat/completions", resolver.HeaderAPIKey, f.appKey)
	require.Equal(t, fiber.StatusOK, status)
	status, _ = callStore(t, app, "/cons1234/v1/chat/completions", resolver.HeaderAPIKey, "ag_alice")
	require.Equal(t, fiber.StatusUnauthorized, status)
	require.Equal(t, lookups, f.finder.calls.Load())
}

func TestAuthMiddleware_StoreAttachesTheOwnerFromEveryAPIKeyHeader(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	app := f.app(func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		principal := &identity.Principal{Subject: "alice", Method: identity.MethodAPIKey}
		authCtx, _ := appauth.AuthContextFromContext(ctx)
		require.Equal(t, &appauth.AuthContext{Principal: principal, Method: appauth.MethodAPIKey, GatewayID: f.gw.ID, GatewaySlug: f.gw.Slug, AuthID: f.ownedID, OwnerID: "alice", Subject: "alice"}, authCtx)
		require.Nil(t, authCtx.KeyBudget, "a key without a budget carries none")
		require.Equal(t, principal, identity.PrincipalFromContext(ctx))
		require.True(t, ctx.Value(appconsumer.ConsumerKey) == nil && c.Locals(string(appconsumer.ConsumerKey)) == nil)
		data, _ := appconsumer.DataFromContext(ctx)
		require.Same(t, f.data, data)
		route, _ := c.Locals(resolver.ProxyRouteLocalsKey).(resolver.ProxyRoute)
		require.Equal(t, consumerdomain.StoreSlug, route.ConsumerSlug)
		return c.SendStatus(fiber.StatusNoContent)
	})
	for _, h := range [][2]string{{resolver.HeaderAPIKey, "ag_alice"}, {resolver.HeaderAPIKeyCompat, "ag_alice"}, {resolver.HeaderAPIKeyGoogle, "ag_alice"}, {fiber.HeaderAuthorization, "Bearer ag_alice"}} {
		status, _ := callStore(t, app, storeChatPath, h[0], h[1])
		require.Equal(t, fiber.StatusNoContent, status, h[0])
	}
}

func TestAuthMiddleware_StoreCarriesACopyOfTheKeyBudget(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	budget := &authdomain.KeyBudget{Max: 50, Unit: authdomain.BudgetUnitDollars, TimeWindow: authdomain.BudgetWindowCalendarMonth}
	f.finder.keys["ag_alice"].Budget = budget
	app := f.app(func(c *fiber.Ctx) error {
		authCtx, _ := appauth.AuthContextFromContext(c.UserContext())
		require.Equal(t, budget, authCtx.KeyBudget)
		require.NotSame(t, budget, authCtx.KeyBudget, "a request never shares the cached key's budget")
		return c.SendStatus(fiber.StatusNoContent)
	})
	status, _ := callStore(t, app, storeChatPath, resolver.HeaderAPIKey, "ag_alice")
	require.Equal(t, fiber.StatusNoContent, status)
}

func TestAuthMiddleware_StoreAnswersInternalErrorWhenALookupFails(t *testing.T) {
	t.Parallel()
	f := newStoreFixture(t)
	f.dataErr = errors.New("down")
	status, _ := callStore(t, f.app(nil), storeChatPath, resolver.HeaderAPIKey, "ag_alice")
	require.Equal(t, fiber.StatusInternalServerError, status)
	require.Zero(t, f.finder.calls.Load())
	f.dataErr, f.finder.err = nil, errors.New("database unavailable")
	status, _ = callStore(t, f.app(nil), storeChatPath, resolver.HeaderAPIKey, "ag_alice")
	require.Equal(t, fiber.StatusInternalServerError, status)
}
