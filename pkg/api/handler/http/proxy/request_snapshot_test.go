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
	c.Locals(string(infracontext.SessionContextKey), c.Get("X-Session"))
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

func TestConsumerTraceSeparatesVerifiedIdentityFromEndUser(t *testing.T) {
	for _, method := range []identity.Method{identity.MethodJWT, identity.MethodIntrospection, identity.MethodMTLS, ""} {
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
			meta := rt.Metadata()
			require.Equal(t, "app-asserted-user", meta.EndUser)
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
