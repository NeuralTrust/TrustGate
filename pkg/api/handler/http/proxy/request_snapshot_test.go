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

package proxy

import (
	"encoding/json"
	"testing"

	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestRequestContextOwnsBuffersBeforeStreaming(t *testing.T) {
	raw := &fasthttp.RequestCtx{}
	raw.Request.SetRequestURI("/original/v1/chat/completions?model=original")
	raw.Request.Header.SetMethod("POST")
	raw.Request.Header.Set("X-Session", "original-session")
	raw.Request.SetBodyString("original-body")
	app := fiber.New()
	c := app.AcquireCtx(raw)
	defer app.ReleaseCtx(c)
	c.SetUserContext(infracontext.WithSession(c.UserContext(), infracontext.Session{
		ID: c.Get("X-Session"), Source: infracontext.SessionSourceConfiguredHeader, Exposed: true,
	}))
	req := buildRequestContext(c, ids.New[ids.GatewayKind](), apiresolver.ProxyRoute{})
	c.Path("/healthz")
	for i := range c.Body() {
		c.Body()[i] = 'x'
	}
	for i := range raw.Request.Header.Peek("X-Session") {
		raw.Request.Header.Peek("X-Session")[i] = 'x'
	}
	raw.Request.URI().QueryArgs().Set("model", "changed")
	require.Equal(t, "/original/v1/chat/completions", req.Path)
	require.Equal(t, "original-body", string(req.Body))
	require.Equal(t, "original-session", req.SessionID)
	require.Equal(t, "original-session", req.Headers["X-Session"][0])
	require.Equal(t, "original", req.Query.Get("model"))
}

// Smart routing's complexity scorer and TrustGuard both read
// RequestContext.SessionID, so a hidden generated id must never land there.
func TestRequestContextCarriesOnlyTheEffectiveSessionID(t *testing.T) {
	cases := []struct {
		name    string
		session infracontext.Session
		want    string
	}{
		{"generated on a stateless request", infracontext.Session{ID: "gen-1", Source: infracontext.SessionSourceGenerated}, ""},
		{"generated on a responses chain", infracontext.Session{ID: "gen-2", Source: infracontext.SessionSourceGenerated, Exposed: true}, "gen-2"},
		{"client header", infracontext.Session{ID: "sess-1", Source: infracontext.SessionSourceKnownHeader, Exposed: true}, "sess-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := &fasthttp.RequestCtx{}
			raw.Request.SetRequestURI("/team/v1/chat/completions")
			raw.Request.Header.SetMethod("POST")
			app := fiber.New()
			c := app.AcquireCtx(raw)
			defer app.ReleaseCtx(c)
			c.SetUserContext(infracontext.WithSession(c.UserContext(), tc.session))
			req := buildRequestContext(c, ids.New[ids.GatewayKind](), apiresolver.ProxyRoute{})
			require.Equal(t, tc.want, req.SessionID)
		})
	}
}

func TestConsumerTraceSeparatesVerifiedIdentityFromEndUser(t *testing.T) {
	for _, method := range []identity.Method{identity.MethodExternalJWT, identity.MethodOAuth, identity.MethodJWT, identity.MethodIntrospection, identity.MethodMTLS, ""} {
		t.Run(string(method), func(t *testing.T) {
			app := fiber.New()
			c := app.AcquireCtx(&fasthttp.RequestCtx{})
			defer app.ReleaseCtx(c)
			rt := trace.New("trace", trace.Metadata{})
			rt.SetEndUser("app-asserted-user")
			ctx := trace.NewContext(c.UserContext(), rt)
			if method != "" {
				ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: "verified-user", Method: method, Claims: map[string]any{"email": "user@example.com"}, RawToken: "never-export-token"})
			}
			c.SetUserContext(ctx)
			stampConsumerTrace(c, &appconsumer.RoutableConsumer{Consumer: &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind](), Name: "test"}})
			stampCallerTrace(c, nil)
			meta := rt.Metadata()
			require.NotNil(t, meta.EndUser)
			require.Equal(t, "app-asserted-user", meta.EndUser.ID)
			require.Equal(t, trace.EndUserSourceNeuralTrust, meta.EndUser.Source)
			require.Equal(t, string(method), meta.PrincipalMethod)
			if method != "" {
				require.Equal(t, "verified-user", meta.PrincipalSubject)
				require.Equal(t, "user@example.com", meta.PrincipalEmail)
			} else {
				require.Empty(t, meta.PrincipalSubject)
				require.Empty(t, meta.PrincipalEmail)
			}
			serialized, err := json.Marshal(meta)
			require.NoError(t, err)
			require.NotContains(t, string(serialized), "never-export-token")
		})
	}
}

func TestConsumerTraceStampsTheAuthIDOnlyWhenOneAuthenticated(t *testing.T) {
	authID := ids.New[ids.AuthKind]()
	keyPrincipal := &identity.Principal{Subject: "billing-service", Method: identity.MethodAPIKey}
	cases := map[string]struct {
		authCtx     *appauth.AuthContext
		principal   *identity.Principal
		wantAuthID  string
		wantSubject string
		wantMethod  string
	}{
		"application key": {
			authCtx:     &appauth.AuthContext{Method: appauth.MethodAPIKey, AuthID: authID, Principal: keyPrincipal},
			principal:   keyPrincipal,
			wantAuthID:  authID.String(),
			wantSubject: "billing-service",
			wantMethod:  string(identity.MethodAPIKey),
		},
		"no auth id":      {authCtx: &appauth.AuthContext{Method: appauth.MethodPlayground}},
		"no auth context": {},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			app := fiber.New()
			c := app.AcquireCtx(&fasthttp.RequestCtx{})
			defer app.ReleaseCtx(c)
			rt := trace.New("trace", trace.Metadata{})
			ctx := trace.NewContext(c.UserContext(), rt)
			if tc.principal != nil {
				ctx = identity.WithPrincipal(ctx, tc.principal)
			}
			c.SetUserContext(ctx)
			stampCallerTrace(c, tc.authCtx)
			meta := rt.Metadata()
			require.Equal(t, tc.wantAuthID, meta.AuthID)
			require.Equal(t, tc.wantSubject, meta.PrincipalSubject)
			require.Equal(t, tc.wantMethod, meta.PrincipalMethod)
		})
	}
}
