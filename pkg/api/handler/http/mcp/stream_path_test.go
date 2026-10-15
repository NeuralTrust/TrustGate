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

package mcp

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

type pathWatchSurface struct {
	appmcp.SurfaceWatcher
	seen chan string
}

func (w *pathWatchSurface) WatchSnapshot(_ context.Context, rc *appconsumer.RoutableConsumer, _ *identity.Principal) string {
	w.seen <- rc.Consumer.Slug
	return rc.Consumer.Slug
}

type pathConsumerFinder struct{ data *appconsumer.Data }

func (f pathConsumerFinder) FindByGateway(context.Context, ids.GatewayID) (*appconsumer.Data, error) {
	return f.data, nil
}

func TestStreamKeepsPathAfterFiberBufferReuse(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	auth := ids.New[ids.AuthKind]()
	original := &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Slug: "original", Active: true, Type: consumerdomain.TypeMCP, AuthIDs: []ids.AuthID{auth}}
	other := *original
	other.ID = ids.New[ids.ConsumerKind]()
	other.Slug = "different"
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{Consumer: original}, {Consumer: &other}})
	surface := &pathWatchSurface{seen: make(chan string, 32)}
	handler := NewHandler(nil, surface, WithConsumerFinder(pathConsumerFinder{data: data}))
	handler.timings = streamTimings{poll: 10 * time.Millisecond, keepAlive: time.Second, lifetime: 100 * time.Millisecond}
	app := fiber.New()
	request := &fasthttp.RequestCtx{}
	request.Request.SetRequestURI("/original/mcp")
	request.Request.Header.Set("Accept", "text/event-stream")
	c := app.AcquireCtx(request)
	defer app.ReleaseCtx(c)
	ctx := appconsumer.WithData(context.Background(), data)
	ctx = appconsumer.WithGatewayID(ctx, gw)
	ctx = appconsumer.WithAuthID(ctx, auth)
	ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: "alice", Method: identity.MethodJWT})
	c.SetUserContext(ctx)
	require.NoError(t, handler.Stream(c))
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, request.Response.BodyStream()); close(done) }()
	select {
	case path := <-surface.seen:
		require.Equal(t, "original", path)
	case <-time.After(time.Second):
		t.Fatal("stream did not start")
	}
	c.Path("/different/mcp")
	select {
	case path := <-surface.seen:
		require.Equal(t, "original", path)
	case <-time.After(time.Second):
		t.Fatal("stream did not poll")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not stop")
	}
}

// The notification stream sits on a catch-all GET, so whatever it answers is
// also what the gateway says about every path it does not serve. 405 with
// "Allow: POST" claims the resource is there and was asked for with the wrong
// verb: true of an MCP endpoint, a lie about anything else. A client walking
// the OAuth discovery chain asks for /.well-known/openid-configuration after
// the authorization-server document, and that lie reads as a server
// misbehaving rather than one with no OpenID metadata.
func TestCatchAllTellsAWrongVerbFromAnUnknownPath(t *testing.T) {
	t.Parallel()
	handler := NewHandler(nil, nil)
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Get("/*", handler.StreamRoute(nil)...)
	app.Delete("/*", handler.NotServedHere)

	cases := []struct {
		name   string
		method string
		path   string
		want   int
		allow  string
	}{
		{
			name:   "an MCP endpoint asked for with a plain GET",
			method: fiber.MethodGet, path: "/store/mcp",
			want: fiber.StatusMethodNotAllowed, allow: fiber.MethodPost,
		},
		{
			name:   "the session-termination DELETE a sessionless gateway does not take",
			method: fiber.MethodDelete, path: "/store/mcp",
			want: fiber.StatusMethodNotAllowed, allow: fiber.MethodPost,
		},
		{
			name:   "OpenID metadata this gateway does not publish",
			method: fiber.MethodGet, path: "/.well-known/openid-configuration",
			want: fiber.StatusNotFound,
		},
		{
			name:   "anything else at all",
			method: fiber.MethodGet, path: "/favicon.ico",
			want: fiber.StatusNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response, err := app.Test(httptest.NewRequest(tc.method, tc.path, nil))
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, tc.want, response.StatusCode)
			require.Equal(t, tc.allow, response.Header.Get(fiber.HeaderAllow))
		})
	}
}
