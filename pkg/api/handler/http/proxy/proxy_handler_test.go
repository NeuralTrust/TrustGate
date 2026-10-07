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

package proxy_test

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	proxyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/proxy"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	labelmocks "github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const consumerSlug = "cons1234"

const proxyPath = "/" + consumerSlug + "/v1/chat/completions"

// authStub mimics the auth middleware: it attaches a resolved gateway id, the
// authenticating auth id and a consumer.Data read model (with one consumer bound
// to proxyPath and authorized for that auth) to the request context, exactly as
// the real api-key auth middleware does.
func authStub(gatewayID ids.GatewayID, slug string) fiber.Handler {
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		{Consumer: &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Slug: slug, Active: true, AuthIDs: []ids.AuthID{authID}}},
	})
	return func(c *fiber.Ctx) error {
		authCtx := &appauth.AuthContext{Method: appauth.MethodAPIKey, GatewayID: gatewayID, AuthID: authID}
		ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
		ctx = appconsumer.WithGatewayID(ctx, gatewayID)
		ctx = appconsumer.WithAuthID(ctx, authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func authStubOAuth(gatewayID ids.GatewayID, slug string) fiber.Handler {
	return authStubWithMethod(gatewayID, slug, appauth.MethodOAuth2)
}

func authStubWithMethod(gatewayID ids.GatewayID, slug string, method appauth.Method) fiber.Handler {
	authID := ids.New[ids.AuthKind]()
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		{Consumer: &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Slug: slug, Active: true, AuthIDs: []ids.AuthID{authID}}},
	})
	return func(c *fiber.Ctx) error {
		authCtx := &appauth.AuthContext{Method: method, GatewayID: gatewayID, AuthID: authID, Subject: "user-1"}
		ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
		ctx = appconsumer.WithGatewayID(ctx, gatewayID)
		ctx = appconsumer.WithAuthID(ctx, authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	}
}

// authStubForbidden mimics the auth middleware authenticating a credential that
// is valid for the gateway but NOT attached to the consumer that matches the
// path, so the handler must reject the request with 403.
func authStubForbidden(gatewayID ids.GatewayID, slug string) fiber.Handler {
	return authStubForbiddenWithMethod(gatewayID, slug, appauth.MethodAPIKey)
}

func authStubForbiddenWithMethod(gatewayID ids.GatewayID, slug string, method appauth.Method) fiber.Handler {
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		{Consumer: &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Slug: slug, Active: true, AuthIDs: []ids.AuthID{ids.New[ids.AuthKind]()}}},
	})
	return func(c *fiber.Ctx) error {
		authCtx := &appauth.AuthContext{Method: method, GatewayID: gatewayID, AuthID: ids.New[ids.AuthKind]()}
		ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
		ctx = appconsumer.WithGatewayID(ctx, gatewayID)
		ctx = appconsumer.WithAuthID(ctx, authCtx.AuthID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func newTestApp(t *testing.T) (*fiber.App, *proxymocks.Forwarder) {
	t.Helper()
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)
	return app, fwd
}

// newUnauthenticatedApp wires the handler with no auth context, simulating an
// unidentified request.
func newUnauthenticatedApp(t *testing.T) (*fiber.App, *proxymocks.Forwarder) {
	t.Helper()
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)
	return app, fwd
}

func newProxyRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, proxyPath, strings.NewReader(`{"model":"gpt"}`))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestHandleCapturesOriginalRequestWithoutTelemetry(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().Forward(mock.Anything, mock.Anything).
		Run(func(ctx context.Context, in appproxy.ForwardInput) {
			original := requestmeta.FromContext(ctx)
			if original == nil || original.IP == "192.0.2.99" || original.IP != in.Request.IP || original.Headers["User-Agent"][0] != "client/1.0" {
				t.Fatalf("incorrect HTTP provenance: %+v", original)
			}
			if _, ok := original.Headers["Authorization"]; ok {
				t.Fatal("credential forwarded")
			}
		}).Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{}`)}, nil).Once()
	req := newProxyRequest()
	req.Header.Set("User-Agent", "client/1.0")
	req.Header.Set("X-Forwarded-For", "192.0.2.99")
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func decodeError(t *testing.T, body io.Reader) httpio.ErrorBody {
	t.Helper()
	var eb httpio.ErrorBody
	if err := json.NewDecoder(body).Decode(&eb); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return eb
}

func TestHandle_Unauthenticated(t *testing.T) {
	app, _ := newUnauthenticatedApp(t)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "unauthenticated" {
		t.Fatalf("error = %q, want unauthenticated", eb.Error)
	}
}

func TestHandle_PathNotFound(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), "other123"))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "not_found" {
		t.Fatalf("error = %q, want not_found", eb.Error)
	}
}

func TestHandle_StoreSlugIsNotFoundWithoutStoreWiring(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), domainconsumer.StoreSlug))
	app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithModels(stubModelsLister{}).Handle)

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/store/v1/chat/completions", strings.NewReader(`{"model":"gpt"}`)),
		httptest.NewRequest(http.MethodGet, "/store/v1/models", nil),
	} {
		resp, err := app.Test(req)
		require.NoError(t, err)
		require.Equal(t, fiber.StatusNotFound, resp.StatusCode, req.URL.Path)
		require.Equal(t, "not_found", decodeError(t, resp.Body).Error)
	}
}

func TestHandle_Forbidden_ConsumerLacksCredential(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStubForbidden(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "forbidden" {
		t.Fatalf("error = %q, want forbidden", eb.Error)
	}
}

func TestHandle_OIDCAttachedAuthSucceeds(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStubWithMethod(ids.New[ids.GatewayKind](), consumerSlug, appauth.MethodOIDC))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)
	fwd.EXPECT().
		Forward(mock.Anything, mock.MatchedBy(func(in appproxy.ForwardInput) bool {
			return in.Consumer != nil && in.Consumer.Consumer != nil && in.Request != nil
		})).
		Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{"ok":true}`)}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// authStubPlayground mimics the auth middleware after the playground identity
// resolver validated a server-minted playground token: MethodPlayground and no
// AuthID.
func authStubPlayground(gatewayID ids.GatewayID, slug string) fiber.Handler {
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		{Consumer: &domainconsumer.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: gatewayID,
			Slug:      slug,
			Active:    true,
		}},
	})
	return func(c *fiber.Ctx) error {
		authCtx := &appauth.AuthContext{Method: appauth.MethodPlayground, GatewayID: gatewayID, Subject: "admin-user"}
		ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
		ctx = appconsumer.WithGatewayID(ctx, gatewayID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func TestHandle_PlaygroundSucceeds(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStubPlayground(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)
	fwd.EXPECT().
		Forward(mock.Anything, mock.MatchedBy(func(in appproxy.ForwardInput) bool {
			return in.Consumer != nil && in.Consumer.Consumer != nil && in.Request != nil
		})).
		Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{"ok":true}`)}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandle_OAuthInlineSucceeds(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStubOAuth(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)
	fwd.EXPECT().
		Forward(mock.Anything, mock.MatchedBy(func(in appproxy.ForwardInput) bool {
			return in.Consumer != nil && in.Consumer.Consumer != nil && in.Request != nil
		})).
		Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{"ok":true}`)}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestHandle_Forbidden_OIDCAuthNotAttached(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStubForbiddenWithMethod(ids.New[ids.GatewayKind](), consumerSlug, appauth.MethodOIDC))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestHandle_Success_RelaysResponse(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.MatchedBy(func(in appproxy.ForwardInput) bool {
			return in.Request != nil && in.Request.Method == http.MethodPost && in.Consumer != nil
		})).
		Return(&appproxy.ForwardResult{
			StatusCode: 200,
			Headers: map[string][]string{
				"Content-Type":        {"application/json"},
				"X-Selected-Provider": {"openai"},
				"X-Request-Id":        {"upstream-request-id"},
				"Transfer-Encoding":   {"chunked"},
			},
			Body: []byte(`{"ok":true}`),
		}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Selected-Provider"); got != "openai" {
		t.Fatalf("X-Selected-Provider = %q, want openai", got)
	}
	if got := resp.Header.Get("X-Request-Id"); got != "" {
		t.Fatalf("X-Request-Id = %q, want empty", got)
	}
	if got := resp.Header.Get("Transfer-Encoding"); got == "chunked" {
		t.Fatal("hop-by-hop Transfer-Encoding header should not be relayed")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", string(body))
	}
}

func TestHandle_Streaming_RelaysSSE(t *testing.T) {
	app, fwd := newTestApp(t)
	lines := [][]byte{
		[]byte("data: {\"delta\":\"hi\"}"),
		{},
		[]byte("data: [DONE]"),
	}
	stream := func(yield func([]byte, error) bool) {
		for _, l := range lines {
			if !yield(l, nil) {
				return
			}
		}
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/event-stream"}, "X-Selected-Provider": {"openai"}},
			Stream:     stream,
		}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}
	if got := resp.Header.Get("X-Selected-Provider"); got != "openai" {
		t.Fatalf("X-Selected-Provider = %q, want openai", got)
	}
	body, _ := io.ReadAll(resp.Body)
	want := "data: {\"delta\":\"hi\"}\n\ndata: [DONE]\n"
	if string(body) != want {
		t.Fatalf("body = %q, want %q", string(body), want)
	}
}

func TestHandle_Streaming_InvokesFinalizerWithCapturedOutput(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	stream := func(yield func([]byte, error) bool) {
		for _, l := range [][]byte{[]byte("data: a"), []byte("data: b")} {
			if !yield(l, nil) {
				return
			}
		}
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
			Stream:     stream,
		}, nil).
		Once()

	var (
		mu         sync.Mutex
		calls      int
		gotOutput  []byte
		gotStatus  int
		gotReqBody []byte
		owned      bool
	)
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(infracontext.StreamMetricsFinalizerKey, infracontext.StreamMetricsFinalizer(
			func(req *infracontext.RequestContext, output []byte, statusCode int, _ map[string][]string) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				gotOutput = output
				gotStatus = statusCode
				gotReqBody = req.Body
			}))
		err := c.Next()
		mu.Lock()
		owned, _ = c.Locals(infracontext.StreamMetricsOwnedKey).(bool)
		mu.Unlock()
		return err
	})
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	_, _ = io.ReadAll(resp.Body)

	mu.Lock()
	defer mu.Unlock()
	if !owned {
		t.Fatal("stream writer must claim metrics ownership")
	}
	if calls != 1 {
		t.Fatalf("finalizer calls = %d, want 1", calls)
	}
	if gotStatus != 200 {
		t.Fatalf("finalizer status = %d, want 200", gotStatus)
	}
	if string(gotOutput) != "data: a\ndata: b\n" {
		t.Fatalf("captured output = %q", string(gotOutput))
	}
	if string(gotReqBody) != `{"model":"gpt"}` {
		t.Fatalf("finalizer req body = %q, want detached request body", string(gotReqBody))
	}
}

func TestHandle_Streaming_MidStreamError(t *testing.T) {
	upstreamErr := errors.New("upstream reset")
	const genericFrame = `data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}`
	const clientFrame = "event: error\ndata: {\"type\":\"error\"}\n"
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "generic error frame appended", err: upstreamErr, want: clientFrame + genericFrame + "\n\n"},
		{name: "client already notified", err: &appproxy.ClientNotifiedStreamError{Err: upstreamErr}, want: clientFrame},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, fwd := newTestApp(t)
			stream := func(yield func([]byte, error) bool) {
				for _, l := range [][]byte{[]byte("event: error"), []byte(`data: {"type":"error"}`)} {
					if !yield(l, nil) {
						return
					}
				}
				yield(nil, tt.err)
			}
			fwd.EXPECT().
				Forward(mock.Anything, mock.Anything).
				Return(&appproxy.ForwardResult{
					StatusCode: 200,
					Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
					Stream:     stream,
				}, nil).
				Once()

			resp, err := app.Test(newProxyRequest())
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != tt.want {
				t.Fatalf("body = %q, want %q", string(body), tt.want)
			}
		})
	}
}

func TestHandle_Streaming_GeminiClientGetsTheGeminiErrorObject(t *testing.T) {
	const geminiFrame = `data: {"error":{"code":500,"message":"upstream stream terminated unexpectedly","status":"INTERNAL"}}`
	const chunk = `data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]}}]}`
	paths := map[string]string{
		"gemini": "/" + consumerSlug + "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
		"vertex": "/" + consumerSlug + "/v1/projects/p/locations/us-central1/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
	}
	tests := map[string]func(yield func([]byte, error) bool){
		"mid-stream error": func(yield func([]byte, error) bool) {
			if yield([]byte(chunk), nil) {
				yield(nil, errors.New("upstream reset"))
			}
		},
		"panic": func(yield func([]byte, error) bool) {
			if yield([]byte(chunk), nil) {
				panic("reader exploded")
			}
		},
	}
	for format, path := range paths {
		for name, stream := range tests {
			t.Run(format+" "+name, func(t *testing.T) {
				fwd := proxymocks.NewForwarder(t)
				app := fiber.New()
				app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
				app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithLogger(slog.New(slog.DiscardHandler)).Handle)
				fwd.EXPECT().
					Forward(mock.Anything, mock.Anything).
					Return(&appproxy.ForwardResult{StatusCode: 200, Stream: stream}, nil).
					Once()

				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"contents":[]}`))
				req.Header.Set("Content-Type", "application/json")
				resp, err := app.Test(req)
				if err != nil {
					t.Fatalf("app.Test: %v", err)
				}
				body, _ := io.ReadAll(resp.Body)
				if want := chunk + "\n" + geminiFrame + "\n"; strings.TrimRight(string(body), "\n")+"\n" != want {
					t.Fatalf("body = %q, want %q", string(body), want)
				}
			})
		}
	}
}

func TestHandle_Streaming_PanicEndsWithErrorEventAndCancels(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithLogger(logger).Handle)

	var forwardCtx context.Context
	stream := func(yield func([]byte, error) bool) {
		if !yield([]byte(`data: {"id":"1"}`), nil) {
			return
		}
		panic("reader exploded")
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Run(func(ctx context.Context, _ appproxy.ForwardInput) { forwardCtx = ctx }).
		Return(&appproxy.ForwardResult{StatusCode: 200, Stream: stream}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	want := `data: {"id":"1"}` + "\n" +
		`data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}` + "\n\n"
	if string(body) != want {
		t.Fatalf("body = %q, want %q", string(body), want)
	}
	if forwardCtx.Err() == nil {
		t.Fatal("the forward context outlived the panicking stream")
	}
	if !strings.Contains(logs.String(), "reader exploded") || !strings.Contains(logs.String(), "stack=") {
		t.Fatalf("panic not logged with its stack: %s", logs.String())
	}
}

func TestHandle_Streaming_PanicLogsTheReaderStack(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithLogger(logger).Handle)

	stream := func(func([]byte, error) bool) {
		panic(&appproxy.ReaderPanic{Value: "reader exploded", Stack: []byte("reader-goroutine-stack")})
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{StatusCode: 200, Stream: stream}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	if !strings.Contains(logs.String(), "panic=\"reader exploded\"") || !strings.Contains(logs.String(), "stack=reader-goroutine-stack") {
		t.Fatalf("reader panic not logged with the reader stack: %s", logs.String())
	}
}

func TestHandle_Streaming_PanicRunsFinalizerOnceWithErrorEvent(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	stream := func(yield func([]byte, error) bool) {
		for _, l := range []string{"data: a", "data: b"} {
			if !yield([]byte(l), nil) {
				return
			}
		}
		panic("reader exploded")
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{StatusCode: 200, Stream: stream}, nil).
		Once()

	var (
		mu        sync.Mutex
		calls     int
		gotOutput []byte
	)
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(infracontext.StreamMetricsFinalizerKey, infracontext.StreamMetricsFinalizer(
			func(_ *infracontext.RequestContext, output []byte, _ int, _ map[string][]string) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				gotOutput = output
			}))
		return c.Next()
	})
	app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithLogger(slog.New(slog.DiscardHandler)).Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("finalizer calls = %d, want 1", calls)
	}
	want := "data: a\ndata: b\n" + `data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}` + "\n"
	if string(gotOutput) != want {
		t.Fatalf("captured output = %q, want %q", string(gotOutput), want)
	}
}

func TestHandle_Streaming_PanicAfterTheStreamEndedWritesNoSecondErrorEvent(t *testing.T) {
	const errorFrame = `data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}`
	upstreamErr := errors.New("upstream reset")
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "after the error event", err: upstreamErr, want: "data: a\n" + errorFrame + "\n\n"},
		{name: "after the client was notified", err: &appproxy.ClientNotifiedStreamError{Err: upstreamErr}, want: "data: a\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd := proxymocks.NewForwarder(t)
			var logs bytes.Buffer
			app := fiber.New()
			app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
			app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithLogger(slog.New(slog.NewTextHandler(&logs, nil))).Handle)

			stream := func(yield func([]byte, error) bool) {
				if !yield([]byte("data: a"), nil) {
					return
				}
				yield(nil, tt.err)
				panic("panic while unwinding")
			}
			fwd.EXPECT().
				Forward(mock.Anything, mock.Anything).
				Return(&appproxy.ForwardResult{StatusCode: 200, Stream: stream}, nil).
				Once()

			resp, err := app.Test(newProxyRequest())
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != tt.want {
				t.Fatalf("body = %q, want %q", string(body), tt.want)
			}
			if !strings.Contains(logs.String(), "panic while unwinding") {
				t.Fatalf("panic after the stream ended was not logged: %s", logs.String())
			}
		})
	}
}

func TestHandle_ForwardContextEndsWithTheResponse(t *testing.T) {
	t.Run("buffered", func(t *testing.T) {
		app, fwd := newTestApp(t)
		var forwardCtx context.Context
		fwd.EXPECT().
			Forward(mock.Anything, mock.Anything).
			Run(func(ctx context.Context, _ appproxy.ForwardInput) { forwardCtx = ctx }).
			Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{"ok":true}`)}, nil).
			Once()

		resp, err := app.Test(newProxyRequest())
		if err != nil {
			t.Fatalf("app.Test: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		if forwardCtx.Err() == nil {
			t.Fatal("the forward context outlived the response")
		}
	})

	t.Run("streamed", func(t *testing.T) {
		app, fwd := newTestApp(t)
		var forwardCtx context.Context
		var errDuringStream error
		stream := func(yield func([]byte, error) bool) {
			errDuringStream = forwardCtx.Err()
			yield([]byte("data: [DONE]"), nil)
		}
		fwd.EXPECT().
			Forward(mock.Anything, mock.Anything).
			Run(func(ctx context.Context, _ appproxy.ForwardInput) { forwardCtx = ctx }).
			Return(&appproxy.ForwardResult{StatusCode: 200, Stream: stream}, nil).
			Once()

		resp, err := app.Test(newProxyRequest())
		if err != nil {
			t.Fatalf("app.Test: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		if errDuringStream != nil {
			t.Fatalf("the forward context ended before the stream was written: %v", errDuringStream)
		}
		if forwardCtx.Err() == nil {
			t.Fatal("the forward context outlived the stream")
		}
	})
}

// A stream guard cut hands the rest of the upstream to a background drain
// that charges its usage; the forward context must outlive the response until
// that drain is done, or the drain reads a cancelled upstream.
func TestHandle_ForwardContextWaitsForTheStreamToSettle(t *testing.T) {
	app, fwd := newTestApp(t)
	var forwardCtx context.Context
	settled := make(chan struct{})
	stream := func(yield func([]byte, error) bool) {
		yield([]byte("data: [DONE]"), nil)
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Run(func(ctx context.Context, _ appproxy.ForwardInput) { forwardCtx = ctx }).
		Return(&appproxy.ForwardResult{
			StatusCode:    200,
			Stream:        stream,
			StreamSettled: func() <-chan struct{} { return settled },
		}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	if forwardCtx.Err() != nil {
		t.Fatal("the forward context ended before the stream settled")
	}
	close(settled)
	select {
	case <-forwardCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the forward context outlived the settled stream")
	}
}

func TestHandle_StreamingClientDisconnectCancelsTheForwardContext(t *testing.T) {
	app, fwd := newTestApp(t)
	forwardCtx := make(chan context.Context, 1)
	stream := func(yield func([]byte, error) bool) {
		ctx := <-forwardCtx
		forwardCtx <- ctx
		for ctx.Err() == nil {
			if !yield([]byte(": keepalive"), nil) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Run(func(ctx context.Context, _ appproxy.ForwardInput) { forwardCtx <- ctx }).
		Return(&appproxy.ForwardResult{StatusCode: 200, Stream: stream}, nil).
		Once()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = app.Listener(listener) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, err = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: gw\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"model\":\"gpt\"}", proxyPath)
	if err != nil {
		t.Fatalf("write request: %v", err)
	}
	if _, err := bufio.NewReader(conn).ReadString(':'); err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = conn.Close()

	ctx := <-forwardCtx
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the forward context was not cancelled after the client went away")
	}
}

func TestHandle_InvalidRequestPayload(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrInvalidRequestPayload).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", eb.Error)
	}
}

func TestHandle_AmbiguousRequestBody(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrAmbiguousRequestBody).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "invalid_request_body" {
		t.Fatalf("error = %q, want invalid_request_body", eb.Error)
	}
}

func TestHandle_InvalidRequestPayload_AnthropicEnvelope(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrInvalidRequestPayload).
		Once()

	req := httptest.NewRequest(http.MethodPost, "/"+consumerSlug+"/v1/messages", strings.NewReader(`{"model":"claude"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), `"type":"error"`) {
		t.Fatalf("body = %s, want anthropic error envelope", raw)
	}
	if !strings.Contains(string(raw), `"invalid_request_error"`) {
		t.Fatalf("body = %s, want invalid_request_error", raw)
	}
}

func TestHandle_StreamingAbort_UsesIngressErrorEvent(t *testing.T) {
	stream := func(yield func([]byte, error) bool) {
		if !yield([]byte("data: a"), nil) {
			return
		}
		_ = yield(nil, errors.New("boom"))
	}

	t.Run("messages", func(t *testing.T) {
		app, fwd := newTestApp(t)
		fwd.EXPECT().
			Forward(mock.Anything, mock.Anything).
			Return(&appproxy.ForwardResult{
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
				Stream:     stream,
			}, nil).
			Once()
		req := httptest.NewRequest(http.MethodPost, "/"+consumerSlug+"/v1/messages", strings.NewReader(`{"model":"claude","max_tokens":8}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("app.Test: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		want := "data: a\n" +
			"event: error\n" +
			`data: {"type":"error","error":{"type":"api_error","message":"upstream stream terminated unexpectedly"}}` +
			"\n\n\n"
		if string(body) != want {
			t.Fatalf("body = %q, want %q", body, want)
		}
	})

	t.Run("chat completions", func(t *testing.T) {
		app, fwd := newTestApp(t)
		fwd.EXPECT().
			Forward(mock.Anything, mock.Anything).
			Return(&appproxy.ForwardResult{
				StatusCode: 200,
				Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
				Stream:     stream,
			}, nil).
			Once()
		resp, err := app.Test(newProxyRequest())
		if err != nil {
			t.Fatalf("app.Test: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		want := "data: a\n" +
			`data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}` +
			"\n\n"
		if string(body) != want {
			t.Fatalf("body = %q, want %q", body, want)
		}
	})
}

func TestHandle_CapabilityNotSupported(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrCapabilityNotSupported).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", eb.Error)
	}
}

func TestHandle_NoBackendAvailable(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrNoBackendsInPool).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestHandle_CredentialAcquisitionReturnsSanitized502(t *testing.T) {
	app, fwd := newTestApp(t)
	idpDetail := "AADSTS7000222: secret expired for app 'ee8407bd' tenant '5ce772a7'"
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("provider completions: %w: %s", registrydomain.ErrCredentialAcquisition, idpDetail)).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	eb := decodeError(t, resp.Body)
	if eb.Error != "provider_credential_error" {
		t.Fatalf("error = %q, want provider_credential_error", eb.Error)
	}
	if eb.Message != registrydomain.ErrCredentialAcquisition.Error() {
		t.Fatalf("message = %q, want sanitized credential message", eb.Message)
	}
	if strings.Contains(eb.Message, "AADSTS") {
		t.Fatal("identity provider details must never be relayed to the client")
	}
}

func TestHandle_RejectionStampsStatusReasonOnTrace(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrModelNotAllowed).
		Once()

	rt := trace.New("trace-reason", trace.Metadata{})
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(trace.NewContext(c.UserContext(), rt))
		return c.Next()
	})
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if got := rt.StatusReason(); got != "model_not_allowed" {
		t.Fatalf("trace status reason = %q, want model_not_allowed", got)
	}
}

func TestHandle_NoRegistryServesModelReturns404ModelNotSupported(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("%w: %q (tried openai, vertex)",
			routingdomain.ErrNoRegistryServesModel, "gemini-3-flash-preview")).
		Once()

	rt := trace.New("trace-no-registry", trace.Metadata{})
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(trace.NewContext(c.UserContext(), rt))
		return c.Next()
	})
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	eb := decodeError(t, resp.Body)
	if eb.Error != "model_not_supported" {
		t.Fatalf("error = %q, want model_not_supported", eb.Error)
	}
	if !strings.Contains(eb.Message, "gemini-3-flash-preview") {
		t.Fatalf("message = %q, want the requested model named", eb.Message)
	}
	if !strings.Contains(eb.Message, "openai") || !strings.Contains(eb.Message, "vertex") {
		t.Fatalf("message = %q, want the probed providers listed", eb.Message)
	}
}

type stubModelsLister struct {
	list *appproxy.ModelsList
	card *appproxy.ModelCard
	err  error
}

func (s stubModelsLister) List(_ context.Context, _ appproxy.ListModelsInput) (*appproxy.ModelsList, error) {
	return s.list, s.err
}

func (s stubModelsLister) Get(_ context.Context, _ appproxy.ListModelsInput, _ string) (*appproxy.ModelCard, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.card, nil
}

func TestHandle_ModelsList(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	lister := stubModelsLister{
		list: &appproxy.ModelsList{
			Object: "list",
			Data:   []appproxy.ModelCard{{ID: "gpt-4o-mini", Object: "model", OwnedBy: "openai"}},
		},
	}
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd).WithModels(lister)
	app.All("/*", handler.Handle)

	req := httptest.NewRequest(http.MethodGet, "/"+consumerSlug+"/v1/models", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body appproxy.ModelsList
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Object != "list" || len(body.Data) != 1 || body.Data[0].ID != "gpt-4o-mini" {
		t.Fatalf("body = %+v", body)
	}
}

func TestHandle_ModelsGet(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	lister := stubModelsLister{
		card: &appproxy.ModelCard{ID: "gpt-4o-mini", Object: "model", OwnedBy: "openai"},
	}
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd).WithModels(lister)
	app.All("/*", handler.Handle)

	req := httptest.NewRequest(http.MethodGet, "/"+consumerSlug+"/v1/models/gpt-4o-mini", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body appproxy.ModelCard
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ID != "gpt-4o-mini" || body.OwnedBy != "openai" {
		t.Fatalf("body = %+v", body)
	}
}

func TestHandle_ModelsGetNotFound(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	lister := stubModelsLister{err: appproxy.ErrModelNotFound}
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd).WithModels(lister)
	app.All("/*", handler.Handle)

	req := httptest.NewRequest(http.MethodGet, "/"+consumerSlug+"/v1/models/missing", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "not_found" {
		t.Fatalf("error = %q, want not_found", eb.Error)
	}
}

func TestHandle_ModelsRejectsNonGET(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	handler := proxyhttp.NewForwardedHandler(fwd).WithModels(stubModelsLister{})
	app.All("/*", handler.Handle)

	req := httptest.NewRequest(http.MethodPost, "/"+consumerSlug+"/v1/models", strings.NewReader(`{}`))
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get(fiber.HeaderAllow); allow != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", allow)
	}
}

func TestHandle_WrongMethodIs405WithoutForwarding(t *testing.T) {
	cases := []struct {
		method string
		path   string
		allow  string
	}{
		{http.MethodGet, "/v1/chat/completions", "POST"},
		{http.MethodGet, "/v1/messages", "POST"},
		{http.MethodGet, "/v1/responses", "POST"},
		{http.MethodGet, "/v1/embeddings", "POST"},
		{http.MethodGet, "/v1/rerank", "POST"},
		{http.MethodGet, "/v1/images/generations", "POST"},
		{http.MethodGet, "/v1/audio/speech", "POST"},
		{http.MethodGet, "/v1/audio/transcriptions", "POST"},
		{http.MethodPut, "/v1/chat/completions", "POST"},
		{http.MethodDelete, "/v1/files", "GET, POST"},
		{http.MethodPost, "/v1/files/file-abc", "GET, DELETE"},
		{http.MethodDelete, "/v1/files/file-abc/content", "GET"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			fwd := proxymocks.NewForwarder(t)
			app := fiber.New()
			app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
			app.All("/*", proxyhttp.NewForwardedHandler(fwd).Handle)

			req := httptest.NewRequest(tc.method, "/"+consumerSlug+tc.path, nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			if resp.StatusCode != fiber.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", resp.StatusCode)
			}
			if allow := resp.Header.Get(fiber.HeaderAllow); allow != tc.allow {
				t.Fatalf("Allow = %q, want %q", allow, tc.allow)
			}
		})
	}
}

func TestOriginalRequestUsesSocketPeerBeforeConfiguredFiberHeader(t *testing.T) {
	for _, mode := range []string{"peer", "gcp"} {
		t.Run(mode, func(t *testing.T) {
			app := fiber.New(fiber.Config{ProxyHeader: fiber.HeaderXForwardedFor})
			app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
			fwd := proxymocks.NewForwarder(t)
			h := proxyhttp.NewForwardedHandler(fwd).WithClientIPResolver(requestmeta.NewIPResolver(mode, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")}))
			app.All("/*", h.Handle)
			fwd.EXPECT().Forward(mock.Anything, mock.Anything).Run(func(ctx context.Context, _ appproxy.ForwardInput) {
				want := "0.0.0.0"
				if mode == "gcp" {
					want = "203.0.113.42"
				}
				original := requestmeta.FromContext(ctx)
				require.NotNil(t, original)
				assert.Equal(t, want, original.IP)
			}).Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{}`)}, nil).Once()
			req := newProxyRequest()
			req.Header.Set(fiber.HeaderXForwardedFor, "192.0.2.99, 203.0.113.42, 34.1.2.3")
			resp, err := app.Test(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
		})
	}
}

// A streamed response is finalized with the handler's own request context, so
// that context must carry the playground verdict the auth stage reached, not
// whatever X-AG-Playground-Token the client sent.
func TestHandle_Streaming_FinalizerReqCarriesPlaygroundVerdict(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	tests := []struct {
		name string
		auth fiber.Handler
		want bool
	}{
		{name: "verified playground auth", auth: authStubPlayground(gwID, consumerSlug), want: true},
		{name: "api key with forged playground header", auth: authStub(gwID, consumerSlug), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd := proxymocks.NewForwarder(t)
			stream := func(yield func([]byte, error) bool) { yield([]byte("data: a"), nil) }
			fwd.EXPECT().
				Forward(mock.Anything, mock.Anything).
				Return(&appproxy.ForwardResult{
					StatusCode: 200,
					Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
					Stream:     stream,
				}, nil).
				Once()

			var (
				mu  sync.Mutex
				got *infracontext.RequestContext
			)
			app := fiber.New()
			app.Use(tt.auth)
			app.Use(func(c *fiber.Ctx) error {
				c.Locals(infracontext.StreamMetricsFinalizerKey, infracontext.StreamMetricsFinalizer(
					func(req *infracontext.RequestContext, _ []byte, _ int, _ map[string][]string) {
						mu.Lock()
						defer mu.Unlock()
						got = req
					}))
				return c.Next()
			})
			app.All("/*", proxyhttp.NewForwardedHandler(fwd).Handle)

			req := newProxyRequest()
			req.Header.Set("X-AG-Playground-Token", "forged")
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			_, _ = io.ReadAll(resp.Body)

			mu.Lock()
			defer mu.Unlock()
			if got == nil {
				t.Fatal("finalizer was not called")
			}
			if got.PlaygroundVerified != tt.want {
				t.Fatalf("PlaygroundVerified = %v, want %v", got.PlaygroundVerified, tt.want)
			}
		})
	}
}

func TestHandle_StampsAuthAndOwnerFromAuthContext(t *testing.T) {
	authID := ids.New[ids.AuthKind]()
	monthlyBudget := &authdomain.KeyBudget{Max: 50, Unit: authdomain.BudgetUnitDollars, TimeWindow: authdomain.BudgetWindowCalendarMonth}
	tests := []struct {
		name                string
		authCtx             appauth.AuthContext
		wantAuth, wantOwner string
		wantBudget          *authdomain.KeyBudget
	}{
		{name: "owned key", authCtx: appauth.AuthContext{Method: appauth.MethodAPIKey, AuthID: authID, OwnerID: "alice"}, wantAuth: authID.String(), wantOwner: "alice"},
		{name: "owned key with a budget", authCtx: appauth.AuthContext{Method: appauth.MethodAPIKey, AuthID: authID, OwnerID: "alice", KeyBudget: monthlyBudget}, wantAuth: authID.String(), wantOwner: "alice", wantBudget: monthlyBudget},
		{name: "budget on another method", authCtx: appauth.AuthContext{Method: appauth.MethodOIDC, AuthID: authID, OwnerID: "alice", KeyBudget: monthlyBudget}},
		{name: "application key", authCtx: appauth.AuthContext{Method: appauth.MethodAPIKey, AuthID: authID}, wantAuth: authID.String()},
		{name: "playground", authCtx: appauth.AuthContext{Method: appauth.MethodPlayground}},
		{name: "oidc", authCtx: appauth.AuthContext{Method: appauth.MethodOIDC, AuthID: authID, OwnerID: "alice"}},
		{name: "mtls", authCtx: appauth.AuthContext{Method: appauth.MethodMTLS, AuthID: authID, OwnerID: "alice"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			authCtx := tt.authCtx
			authCtx.GatewayID = gatewayID
			data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
				{Consumer: &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Slug: consumerSlug, Active: true, AuthIDs: []ids.AuthID{authID}}},
			})
			fwd := proxymocks.NewForwarder(t)
			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				c.SetUserContext(appconsumer.WithData(appconsumer.WithGatewayID(appauth.WithAuthContext(c.UserContext(), &authCtx), gatewayID), data))
				return c.Next()
			})
			app.All("/*", proxyhttp.NewForwardedHandler(fwd).Handle)
			var got *infracontext.RequestContext
			fwd.EXPECT().Forward(mock.Anything, mock.Anything).
				Run(func(_ context.Context, in appproxy.ForwardInput) {
					got = in.Request
					assert.False(t, in.Prechecked)
				}).
				Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{}`)}, nil).Once()

			req := newProxyRequest()
			req.Header.Set("X-AG-Owner-Id", "mallory")
			req.Header.Set("X-AG-Auth-Id", "forged")
			resp, err := app.Test(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, fiber.StatusOK, resp.StatusCode)
			require.NotNil(t, got)
			assert.Equal(t, tt.wantAuth, got.AuthID)
			assert.Equal(t, tt.wantOwner, got.OwnerID)
			assert.Equal(t, tt.wantBudget, got.KeyBudget)
		})
	}
}

type personalSpec struct {
	provider, extra string
	allowed         []string
	level           domainconsumer.GrantLevel
	labeled         bool
}

func storeData(gatewayID ids.GatewayID, authID ids.AuthID, specs ...personalSpec) *appconsumer.Data {
	global := &policydomain.Policy{Name: "global", Global: true}
	consumers := make([]appconsumer.RoutableConsumer, 0, len(specs))
	for i, spec := range specs {
		reg := storeRegistry(gatewayID, spec.provider)
		name := fmt.Sprintf("P%d", i+1)
		rc := appconsumer.RoutableConsumer{
			Consumer: &domainconsumer.Consumer{
				ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Name: name, Slug: fmt.Sprintf("pers%04d", i+1), Active: true,
				Audience: domainconsumer.AudiencePersonal, AuthIDs: []ids.AuthID{authID},
				AuthLinks: map[ids.AuthID]domainconsumer.AuthLink{
					authID: {Level: cmp.Or(spec.level, domainconsumer.GrantLevelGroup), Priority: i, GrantedAt: time.Unix(0, 0)},
				},
				ModelPolicies: domainconsumer.ModelPolicies{reg.ID: {Allowed: spec.allowed}},
			},
			Registries: []*registrydomain.Registry{reg},
			Policies:   []*policydomain.Policy{{Name: name}, global},
			PolicyPlan: &appplugins.StagePlan{},
		}
		if spec.extra != "" {
			rc.Registries = append(rc.Registries, storeRegistry(gatewayID, spec.extra))
		}
		if spec.labeled {
			rc.Consumer.LabelSets = []trafficlabel.LabelSet{{ID: "set-topic", Name: "Topic", Labels: []trafficlabel.Label{{Name: "Billing"}}}}
		}
		consumers = append(consumers, rc)
	}
	data := appconsumer.NewData(gatewayID, consumers)
	data.StoreConsumer = &appconsumer.RoutableConsumer{Policies: []*policydomain.Policy{{Name: "mcp-wide"}}}
	return data
}

func storeRegistry(gatewayID ids.GatewayID, provider string) *registrydomain.Registry {
	return &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gatewayID, Type: registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{Provider: provider}}
}

func ownerAuth(gatewayID ids.GatewayID, authID ids.AuthID) *appauth.AuthContext {
	return &appauth.AuthContext{Method: appauth.MethodAPIKey, GatewayID: gatewayID, AuthID: authID, OwnerID: "alice", Subject: "alice"}
}

func newStoreApp(
	t *testing.T,
	data *appconsumer.Data,
	authCtx *appauth.AuthContext,
	limited *appproxy.ForwardResult,
	before ...fiber.Handler,
) (*fiber.App, *proxymocks.Forwarder, *trace.RequestTrace) {
	t.Helper()
	fwd := proxymocks.NewForwarder(t)
	fwd.EXPECT().Precheck(mock.Anything, data.GatewayID, mock.Anything).Return(limited, nil).Maybe()
	app, rt := newStoreAppWith(data, authCtx, fwd, before...)
	return app, fwd, rt
}

func newStoreAppWith(
	data *appconsumer.Data,
	authCtx *appauth.AuthContext,
	fwd appproxy.Forwarder,
	before ...fiber.Handler,
) (*fiber.App, *trace.RequestTrace) {
	rt := trace.New("store-trace", trace.Metadata{})
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appauth.WithAuthContext(trace.NewContext(c.UserContext(), rt), authCtx)
		ctx = identity.WithPrincipal(ctx, &identity.Principal{Subject: authCtx.OwnerID, Method: identity.MethodAPIKey})
		c.SetUserContext(appconsumer.WithData(appconsumer.WithGatewayID(ctx, data.GatewayID), data))
		return c.Next()
	})
	for _, handler := range before {
		app.Use(handler)
	}
	resolver := approuting.NewResolver()
	selector := appproxy.NewStoreSelector(resolver, nil, slog.New(slog.DiscardHandler))
	app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithStore(selector, appproxy.NewStoreModels(resolver, nil)).Handle)
	return app, rt
}

func storeChat(model string) *http.Request {
	return storeChatBody(`{"model":"` + model + `"}`)
}

func storeChatBody(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/store/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestHandleStore_ForbiddenWithoutAnUpstreamCall(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	cases := []struct {
		name   string
		linked ids.AuthID
		model  string
	}{
		{name: "denied model", linked: authID, model: "claude-sonnet-4-5"},
		{name: "no links", linked: ids.New[ids.AuthKind](), model: "gpt-4o-mini"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := storeData(gatewayID, tc.linked, personalSpec{provider: "openai", allowed: []string{"gpt-4o*"}})
			app, _, rt := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil)
			resp, err := app.Test(storeChat(tc.model))
			require.NoError(t, err)
			assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
			assert.Equal(t, "model_not_allowed", decodeError(t, resp.Body).Error)
			assert.Equal(t, authID.String(), rt.Metadata().AuthID)
			assert.Equal(t, "alice", rt.Metadata().PrincipalSubject)
			assert.Empty(t, rt.Metadata().ConsumerID)
		})
	}
}

func TestHandleStore_RejectionsBeforeForwarding(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "openai", allowed: []string{"gpt-4o*"}})
	limited := &appproxy.ForwardResult{StatusCode: fiber.StatusTooManyRequests, Headers: map[string][]string{"Retry-After": {"10"}}}
	cases := []struct {
		name    string
		req     *http.Request
		limited *appproxy.ForwardResult
		status  int
		code    string
	}{
		{name: "method not allowed", req: httptest.NewRequest(http.MethodGet, "/store/v1/chat/completions", nil),
			status: fiber.StatusMethodNotAllowed, code: "method_not_allowed"},
		{name: "ambiguous body", req: storeChatBody(`{"model":"gpt-4o-mini","model":"gpt-4o"}`),
			status: fiber.StatusBadRequest, code: "invalid_request_body"},
		{name: "rate limited after selection", req: storeChat("gpt-4o-mini"), limited: limited,
			status: fiber.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, _, rt := newStoreApp(t, data, ownerAuth(gatewayID, authID), tc.limited)
			resp, err := app.Test(tc.req)
			require.NoError(t, err)
			require.Equal(t, tc.status, resp.StatusCode)
			if tc.code != "" {
				assert.Equal(t, tc.code, decodeError(t, resp.Body).Error)
			}
			assert.Equal(t, authID.String(), rt.Metadata().AuthID)
			assert.Empty(t, rt.Metadata().ConsumerID)
		})
	}
}

func TestHandleStore_DeniedModelSpendsNoPlanToken(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "openai", allowed: []string{"gpt-4o*"}})
	fwd := proxymocks.NewForwarder(t)
	app, _ := newStoreAppWith(data, ownerAuth(gatewayID, authID), fwd)

	resp, err := app.Test(storeChat("claude-sonnet-4-5"))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	fwd.AssertNotCalled(t, "Precheck", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleStore_AmbiguousBodyAnswers400WithoutARateLimitToken(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "openai", allowed: []string{"gpt-4o*"}})
	forwarder := appproxy.NewForwarder(nil, nil, cache.NewTTLMapManager(time.Minute), nil, nil, nil, nil, nil,
		ratelimitmocks.NewChecker(t), nil, slog.New(slog.DiscardHandler))
	app, _ := newStoreAppWith(data, ownerAuth(gatewayID, authID), forwarder)

	resp, err := app.Test(storeChatBody(`{"model":"gpt-4o-mini","model":"gpt-4o"}`))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_request_body", decodeError(t, resp.Body).Error)
}

func TestHandleStore_FilesRoutesAreNotServed(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "openai"})
	unknownApp, _, _ := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil)
	unknown, err := unknownApp.Test(httptest.NewRequest(http.MethodGet, "/store/v1/nowhere", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusNotFound, unknown.StatusCode)
	wantBody, err := io.ReadAll(unknown.Body)
	require.NoError(t, err)

	upload := httptest.NewRequest(http.MethodPost, "/store/v1/files", strings.NewReader("--b\r\n"))
	upload.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	for name, req := range map[string]*http.Request{
		"list":    httptest.NewRequest(http.MethodGet, "/store/v1/files", nil),
		"get":     httptest.NewRequest(http.MethodGet, "/store/v1/files/file-abc123", nil),
		"content": httptest.NewRequest(http.MethodGet, "/store/v1/files/file-abc123/content", nil),
		"delete":  httptest.NewRequest(http.MethodDelete, "/store/v1/files/file-abc123", nil),
		"upload":  upload,
	} {
		t.Run(name, func(t *testing.T) {
			app, fwd, rt := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil)
			resp, err := app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, string(wantBody), string(body))
			fwd.AssertNotCalled(t, "Precheck", mock.Anything, mock.Anything, mock.Anything)
			assert.Empty(t, rt.Metadata().ConsumerID)
		})
	}
}

func TestHandleStore_AttributesTheRequestToTheKeyOwner(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "openai", allowed: []string{"gpt-4o-mini"}})
	named := storeChat("gpt-4o-mini")
	named.Header.Set(domainconsumer.EndUserHeader, "mallory")
	malformed := storeChat("gpt-4o-mini")
	malformed.Header.Set(domainconsumer.EndUserHeader, strings.Repeat("x", domainconsumer.MaxEndUserLength+1))
	cases := []struct {
		name    string
		req     *http.Request
		forward bool
	}{
		{name: "end-user header naming someone else", req: named, forward: true},
		{name: "malformed end-user header", req: malformed, forward: true},
		{name: "models listing", req: httptest.NewRequest(http.MethodGet, "/store/v1/models", nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frontEnd := trace.New("front-end", trace.Metadata{EndUser: &trace.EndUser{ID: "someone", Email: "x@acme.test", Source: "open_webui"}})
			withFrontEnd := func(c *fiber.Ctx) error {
				c.SetUserContext(trace.NewContext(c.UserContext(), frontEnd))
				return c.Next()
			}
			app, fwd, _ := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil, withFrontEnd)
			if tc.forward {
				fwd.EXPECT().Forward(mock.Anything, mock.Anything).
					Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{}`)}, nil).Once()
			}
			resp, err := app.Test(tc.req)
			require.NoError(t, err)
			require.Equal(t, fiber.StatusOK, resp.StatusCode)
			assert.Equal(t, &trace.EndUser{ID: "alice", Source: trace.EndUserSourceNeuralTrust}, frontEnd.Metadata().EndUser)
		})
	}
}

func TestHandleStore_RequiresAPersonalAPIKey(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "openai"})
	for name, authCtx := range map[string]*appauth.AuthContext{
		"api key without an owner": {Method: appauth.MethodAPIKey, GatewayID: gatewayID, AuthID: authID},
		"owner on another method":  {Method: appauth.MethodOIDC, GatewayID: gatewayID, AuthID: authID, OwnerID: "alice"},
	} {
		t.Run(name, func(t *testing.T) {
			app, _, _ := newStoreApp(t, data, authCtx, nil)
			resp, err := app.Test(storeChat("gpt-4o"))
			require.NoError(t, err)
			assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		})
	}
}

func TestHandleStore_ServesThroughTheSelectedConsumer(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID,
		personalSpec{provider: "anthropic", allowed: []string{"claude-*"}},
		personalSpec{provider: "openai", allowed: []string{"gpt-4o*"}})
	selected := data.StoreLinks(authID)[1].Consumer
	app, fwd, rt := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil)
	var in appproxy.ForwardInput
	var forwardedAuth *appauth.AuthContext
	fwd.EXPECT().Forward(mock.Anything, mock.Anything).
		Run(func(ctx context.Context, got appproxy.ForwardInput) {
			in = got
			forwardedAuth, _ = appauth.AuthContextFromContext(ctx)
		}).
		Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{}`)}, nil).Once()

	resp, err := app.Test(storeChat("gpt-4o-mini"))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	assert.Same(t, selected, in.Consumer)
	require.Len(t, in.Consumer.Policies, 2)
	assert.Equal(t, []string{"P2", "global"}, []string{in.Consumer.Policies[0].Name, in.Consumer.Policies[1].Name})
	require.NotNil(t, in.Resolved)
	assert.Equal(t, "gpt-4o-mini", in.Resolved.Ref)
	assert.True(t, in.Prechecked)
	assert.Equal(t, domainconsumer.StoreSlug, in.RouteSlug)
	assert.Equal(t, authID.String(), in.Request.AuthID)
	assert.Equal(t, "alice", in.Request.OwnerID)
	require.NotNil(t, forwardedAuth)
	assert.Equal(t, selected.Consumer.ID, forwardedAuth.ConsumerID)
	meta := rt.Metadata()
	assert.Equal(t, selected.Consumer.ID.String(), meta.ConsumerID)
	assert.Equal(t, authID.String(), meta.AuthID)
	assert.Equal(t, "alice", meta.PrincipalSubject)
	assert.Equal(t, string(identity.MethodAPIKey), meta.PrincipalMethod)
}

func TestHandleStore_UserLinkKeepsTheSubstitutedProviderOut(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID,
		personalSpec{provider: "openai", extra: "mistral", allowed: []string{"gpt-4o*"}},
		personalSpec{provider: "openai", allowed: []string{"gpt6"}, level: domainconsumer.GrantLevelUser})
	group := data.StoreLinks(authID)[1].Consumer
	require.Equal(t, "P1", group.Consumer.Name)
	app, fwd, _ := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil)
	var in appproxy.ForwardInput
	fwd.EXPECT().Forward(mock.Anything, mock.Anything).
		Run(func(_ context.Context, got appproxy.ForwardInput) { in = got }).
		Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{}`)}, nil).Once()

	resp, err := app.Test(storeChat("mistral-large"))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Same(t, group, in.Consumer)
	assert.Equal(t, []*registrydomain.Registry{group.Registries[1]}, in.Resolved.Candidates.Registries())
}

func TestHandleStore_StreamsThroughTheSharedTail(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "openai", allowed: []string{"gpt-4o*"}})
	app, fwd, _ := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil)
	fwd.EXPECT().Forward(mock.Anything, mock.Anything).Return(&appproxy.ForwardResult{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
		Stream: func(yield func([]byte, error) bool) {
			_ = yield([]byte("data: [DONE]"), nil)
		},
	}, nil).Once()

	resp, err := app.Test(storeChat("gpt-4o-mini"))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "data: [DONE]\n", string(body))
}

func TestHandleStore_TrafficLabelingDoesNotSeeStoreRequests(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID, personalSpec{provider: "openai", allowed: []string{"gpt-4o*"}, labeled: true})
	gw, err := gatewaydomain.New("acme")
	require.NoError(t, err)
	gw.TrafficLabeling = &trafficlabel.Config{Enabled: true, RegistryID: ids.New[ids.RegistryKind]().String(), Model: "gpt-4o-mini"}
	labels := middleware.NewTrafficLabelsMiddleware(labelmocks.NewIntake(t), labelmocks.NewRecorder(t), &config.Config{})
	withGateway := func(c *fiber.Ctx) error {
		c.SetUserContext(appgateway.WithGateway(c.UserContext(), gw))
		return c.Next()
	}
	app, fwd, _ := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil, withGateway, labels.Middleware())
	fwd.EXPECT().Forward(mock.Anything, mock.Anything).Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{}`)}, nil).Once()

	resp, err := app.Test(storeChat("gpt-4o-mini"))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestHandleStore_ModelsListTheUnionAndStampNoConsumer(t *testing.T) {
	gatewayID, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	data := storeData(gatewayID, authID,
		personalSpec{provider: "anthropic", allowed: []string{"claude-sonnet-4-5"}},
		personalSpec{provider: "openai", allowed: []string{"gpt-4o-mini"}})
	app, _, rt := newStoreApp(t, data, ownerAuth(gatewayID, authID), nil)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/store/v1/models", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	var list appproxy.ModelsList
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&list))
	require.Len(t, list.Data, 2)
	assert.Equal(t, []string{"claude-sonnet-4-5", "gpt-4o-mini"}, []string{list.Data[0].ID, list.Data[1].ID})
	resp, err = app.Test(httptest.NewRequest(http.MethodGet, "/store/v1/models/gpt-4.1", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	assert.Empty(t, rt.Metadata().ConsumerID)
	assert.Equal(t, authID.String(), rt.Metadata().AuthID)
}
