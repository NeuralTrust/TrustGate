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
	"crypto/x509"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infrajwt "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	agentIdPIssuer        = "https://idp.example.com"
	agentPlaygroundSecret = "agent-playground-secret"
)

func agentPlaygroundToken(t *testing.T, slug string) string {
	t.Helper()
	claims := &infrajwt.Claims{UserID: "user-1", Purpose: infrajwt.PurposePlayground, ConsumerSlug: slug}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(agentPlaygroundSecret))
	require.NoError(t, err)
	return token
}

type keyFinder map[string]*authdomain.Auth

func (f keyFinder) FindByAPIKey(_ context.Context, raw string) (*authdomain.Auth, error) {
	if a, ok := f[raw]; ok {
		return a, nil
	}
	return nil, authdomain.ErrNotFound
}

// agentPaths scopes a path to the auths attached to the consumer it names.
type agentPaths map[string]*consumerdomain.Consumer

func (p agentPaths) Match(_ context.Context, _, path string) ([]appconsumer.PathMatch, error) {
	c, ok := p[appconsumer.SlugFromAgentPath(path)]
	if !ok {
		return nil, nil
	}
	m := appconsumer.PathMatch{GatewayID: c.GatewayID, Consumer: c}
	for _, id := range c.AuthIDs {
		m.Auths = append(m.Auths, &authdomain.Auth{ID: id})
	}
	return []appconsumer.PathMatch{m}, nil
}

type agentFixture struct {
	app      *fiber.App
	bot      *consumerdomain.Consumer
	appKey   *authdomain.Auth
	otherKey *authdomain.Auth
	jwt      *fakeTokenValidator
	mtls     *fakeMTLSValidator
	got      *identity.Principal
	consumer *appconsumer.RoutableConsumer
	auth     *appauth.AuthContext
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	appKey, err := authdomain.NewAPIKeyAuth(gw.ID, "bot-key", true, nil)
	require.NoError(t, err)
	otherKey, err := authdomain.NewAPIKeyAuth(gw.ID, "other-key", true, nil)
	require.NoError(t, err)
	idp, err := authdomain.NewAuth(gw.ID, "idp", authdomain.TypeOAuth2, true, authdomain.Config{
		OAuth2: &authdomain.OAuth2Config{Issuer: agentIdPIssuer, JWKSURL: agentIdPIssuer + "/jwks", Audiences: []string{"trustgate"}},
	})
	require.NoError(t, err)
	mtlsAuth, err := authdomain.NewAuth(gw.ID, "mtls", authdomain.TypeMTLS, true,
		authdomain.Config{MTLS: &authdomain.MTLSConfig{CACert: "ca"}})
	require.NoError(t, err)

	consumer := func(slug string, typ consumerdomain.Type, auths ...ids.AuthID) *consumerdomain.Consumer {
		return &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Name: slug, Slug: slug,
			Type: typ, Active: true, AuthIDs: auths,
		}
	}
	bot := consumer("bot", consumerdomain.TypeA2A, appKey.ID, idp.ID, mtlsAuth.ID)
	bot.AuthBinding = consumerdomain.AuthBinding{
		AllowedClientIDs:           []string{"good-client"},
		AllowedCertificateSubjects: []string{"good.svc"},
	}
	other := consumer("other", consumerdomain.TypeA2A, otherKey.ID)
	tools := consumer("tools", consumerdomain.TypeMCP, appKey.ID)

	f := &agentFixture{
		bot:      bot,
		appKey:   appKey,
		otherKey: otherKey,
		jwt:      &fakeTokenValidator{},
		mtls:     &fakeMTLSValidator{},
	}
	resolver := middleware.NewAgentChainIdentityResolver(
		keyFinder{appKey.RawKey: appKey, otherKey.RawKey: otherKey},
		fakeCredentialFinder{oauth2: []*authdomain.Auth{idp}, mtls: []*authdomain.Auth{mtlsAuth}},
		agentPaths{"bot": bot, "other": other, "tools": tools},
		f.jwt, &fakeTokenValidator{}, f.mtls,
		&fakeCertExtractor{cert: &x509.Certificate{}},
		[]string{"0.0.0.0/0", "::/0"},
	)
	data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{{Consumer: bot}, {Consumer: other}, {Consumer: tools}})
	playground := apiresolver.NewPlaygroundIdentityResolver(
		infrajwt.NewPlaygroundVerifier(&config.ServerConfig{SecretKey: agentPlaygroundSecret}, nil))
	m := middleware.NewAgentAuthMiddleware(resolver, stubDataFinder{data: data}, stubGatewayFinder{gw: gw}, playground)

	f.app = fiber.New()
	f.app.Post("/:consumer/agents/:agent", m.Middleware(), func(c *fiber.Ctx) error {
		f.got = identity.PrincipalFromContext(c.UserContext())
		f.consumer, _ = appconsumer.ConsumerFromContext(c.UserContext())
		f.auth, _ = appauth.AuthContextFromContext(c.UserContext())
		return c.SendStatus(fiber.StatusOK)
	})
	return f
}

func (f *agentFixture) call(t *testing.T, path string, headers map[string]string) int {
	t.Helper()
	f.got, f.consumer, f.auth = nil, nil, nil
	req := httptest.NewRequest(fiber.MethodPost, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := f.app.Test(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	return resp.StatusCode
}

func idpToken(t *testing.T) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": agentIdPIssuer, "sub": "alice", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test-only"))
	require.NoError(t, err)
	return raw
}

func TestAgentAuth_APIKeyRunsAsTheApplication(t *testing.T) {
	f := newAgentFixture(t)
	require.Equal(t, fiber.StatusOK, f.call(t, "/bot/agents/research", map[string]string{apiresolver.HeaderAPIKey: f.appKey.RawKey}))
	require.Equal(t, f.bot.ID, f.consumer.Consumer.ID)
	require.Equal(t, consumerdomain.AppSubject(f.bot.ID), f.got.Subject)
	require.Equal(t, identity.MethodAPIKey, f.got.Method)
	require.Equal(t, "bot-key", f.got.Claims[identity.ClaimCredentialSubject])
}

func TestAgentAuth_APIKeyAsBearer(t *testing.T) {
	f := newAgentFixture(t)
	require.Equal(t, fiber.StatusOK, f.call(t, "/bot/agents/research", map[string]string{"Authorization": "Bearer " + f.appKey.RawKey}))
	require.Equal(t, consumerdomain.AppSubject(f.bot.ID), f.got.Subject)
}

func TestAgentAuth_EndUserHeaderSwapsThePrincipal(t *testing.T) {
	f := newAgentFixture(t)
	status := f.call(t, "/bot/agents/research", map[string]string{
		apiresolver.HeaderAPIKey:     f.appKey.RawKey,
		consumerdomain.EndUserHeader: "alice@example.com",
	})
	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, consumerdomain.EndUserSubject(f.bot.ID, "alice@example.com"), f.got.Subject)
	require.Equal(t, "alice@example.com", f.got.Claims["end_user"])
	require.Equal(t, "bot-key", f.got.Claims["app_subject"])

	status = f.call(t, "/bot/agents/research", map[string]string{
		apiresolver.HeaderAPIKey:     f.appKey.RawKey,
		consumerdomain.EndUserHeader: strings.Repeat("u", consumerdomain.MaxEndUserLength+1),
	})
	require.Equal(t, fiber.StatusBadRequest, status)
}

func TestAgentAuth_MTLSThroughXFCC(t *testing.T) {
	f := newAgentFixture(t)
	f.mtls.principal = &identity.Principal{
		Subject: "good.svc", Method: identity.MethodMTLS,
		Claims: map[string]any{"common_name": "good.svc"},
	}
	require.Equal(t, fiber.StatusOK, f.call(t, "/bot/agents/research", map[string]string{"X-Forwarded-Client-Cert": `Cert="x"`}))
	require.Equal(t, consumerdomain.AppSubject(f.bot.ID), f.got.Subject)
	require.Equal(t, identity.MethodMTLS, f.got.Method)

	f.mtls.principal = &identity.Principal{
		Subject: "bad.svc", Method: identity.MethodMTLS,
		Claims: map[string]any{"common_name": "bad.svc"},
	}
	require.Equal(t, fiber.StatusForbidden, f.call(t, "/bot/agents/research", map[string]string{"X-Forwarded-Client-Cert": `Cert="x"`}))
}

func TestAgentAuth_IdPTokenKeepsItsSubject(t *testing.T) {
	f := newAgentFixture(t)
	f.jwt.principal = &identity.Principal{
		Subject: "alice", Method: identity.MethodExternalJWT,
		Claims: map[string]any{"azp": "good-client"},
	}
	headers := map[string]string{"Authorization": "Bearer " + idpToken(t), consumerdomain.EndUserHeader: "mallory"}
	require.Equal(t, fiber.StatusOK, f.call(t, "/bot/agents/research", headers))
	require.Equal(t, "alice", f.got.Subject, "a token's subject is never replaced by the end-user header")

	f.jwt.principal.Claims = map[string]any{"azp": "other-client"}
	require.Equal(t, fiber.StatusForbidden, f.call(t, "/bot/agents/research", headers))
}

func TestAgentAuth_Refusals(t *testing.T) {
	f := newAgentFixture(t)
	require.Equal(t, fiber.StatusUnauthorized, f.call(t, "/bot/agents/research", nil))
	require.Equal(t, fiber.StatusUnauthorized, f.call(t, "/bot/agents/research", map[string]string{apiresolver.HeaderAPIKey: "ag_unknown"}))
	require.Equal(t, fiber.StatusForbidden, f.call(t, "/bot/agents/research", map[string]string{apiresolver.HeaderAPIKey: f.otherKey.RawKey}),
		"a key attached only to another application")
	require.Equal(t, fiber.StatusNotFound, f.call(t, "/tools/agents/research", map[string]string{apiresolver.HeaderAPIKey: f.appKey.RawKey}),
		"an MCP consumer is not served on the agent plane")
	require.Equal(t, fiber.StatusNotFound, f.call(t, "/nobody/agents/research", map[string]string{apiresolver.HeaderAPIKey: f.appKey.RawKey}))
}

func TestAgentAuth_RefusesMCPSessionTokens(t *testing.T) {
	f := newAgentFixture(t)
	_, signer := sessionVerifier(t)
	token := mintSession(t, signer, jwt.MapClaims{"sub": "u", "authid": f.appKey.ID.String(), "token_use": "mcp_session"})
	require.Equal(t, fiber.StatusUnauthorized, f.call(t, "/bot/agents/research", map[string]string{"Authorization": "Bearer " + token}))
}

// The console's playground calls an agent with a playground token bound to the
// application: it runs as the console user inside it, and is marked as a
// playground call. A token for another application, or a forged one, is refused.
func TestAgentAuth_PlaygroundToken(t *testing.T) {
	f := newAgentFixture(t)

	headers := func(token string) map[string]string {
		return map[string]string{apiresolver.HeaderPlaygroundToken: token, apiresolver.HeaderGatewaySlug: "acme"}
	}
	require.Equal(t, fiber.StatusOK, f.call(t, "/bot/agents/a-1", headers(agentPlaygroundToken(t, "bot"))))
	require.Equal(t, "bot", f.consumer.Consumer.Slug)
	require.Equal(t, consumerdomain.EndUserSubject(f.bot.ID, "user-1"), f.got.Subject)
	require.Equal(t, appauth.MethodPlayground, f.auth.Method)

	require.Equal(t, fiber.StatusForbidden, f.call(t, "/bot/agents/a-1", headers(agentPlaygroundToken(t, "other"))))
	require.Equal(t, fiber.StatusUnauthorized, f.call(t, "/bot/agents/a-1", headers("forged")))
	require.Equal(t, fiber.StatusNotFound, f.call(t, "/tools/agents/a-1", headers(agentPlaygroundToken(t, "tools"))))
}
