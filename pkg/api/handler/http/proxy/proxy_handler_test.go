package proxy_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	proxyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/proxy"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/AgentGateway/pkg/app/proxy/mocks"
	domainconsumer "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
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

func authStubOAuth2Client(gatewayID ids.GatewayID, slug string) fiber.Handler {
	return authStubWithMethod(gatewayID, slug, appauth.MethodOAuth2Client)
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
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		{Consumer: &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gatewayID, Slug: slug, Active: true, AuthIDs: []ids.AuthID{ids.New[ids.AuthKind]()}}},
	})
	return func(c *fiber.Ctx) error {
		authCtx := &appauth.AuthContext{Method: appauth.MethodAPIKey, GatewayID: gatewayID, AuthID: ids.New[ids.AuthKind]()}
		ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
		ctx = appconsumer.WithGatewayID(ctx, gatewayID)
		ctx = appconsumer.WithAuthID(ctx, authCtx.AuthID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func authStubRoleBased(gatewayID ids.GatewayID, slug string, consumerRoles, effectiveRoles []ids.RoleID) fiber.Handler {
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		{Consumer: &domainconsumer.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gatewayID,
			Slug:        slug,
			Active:      true,
			RoutingMode: domainconsumer.RoutingModeRoleBased,
			RoleIDs:     consumerRoles,
		}},
	})
	return func(c *fiber.Ctx) error {
		authCtx := &appauth.AuthContext{Method: appauth.MethodIDP, GatewayID: gatewayID, Subject: "user-1", RoleIDs: effectiveRoles}
		ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
		ctx = appconsumer.WithGatewayID(ctx, gatewayID)
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

func decodeError(t *testing.T, body io.Reader) helpers.ErrorBody {
	t.Helper()
	var eb helpers.ErrorBody
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

func TestHandle_Forbidden_APIKeyCannotAuthorizeRoleBasedConsumer(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	gwID := ids.New[ids.GatewayKind]()
	roleID := ids.New[ids.RoleKind]()
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: &domainconsumer.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gwID,
			Slug:        consumerSlug,
			Active:      true,
			RoutingMode: domainconsumer.RoutingModeRoleBased,
			RoleIDs:     []ids.RoleID{roleID},
		}},
	})
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		authID := ids.New[ids.AuthKind]()
		authCtx := &appauth.AuthContext{Method: appauth.MethodAPIKey, GatewayID: gwID, AuthID: authID}
		ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
		ctx = appconsumer.WithGatewayID(ctx, gwID)
		ctx = appconsumer.WithAuthID(ctx, authID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	})
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

func TestHandle_RoleBasedIDPIntersectionSucceeds(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	gwID := ids.New[ids.GatewayKind]()
	roleID := ids.New[ids.RoleKind]()
	app := fiber.New()
	app.Use(authStubRoleBased(gwID, consumerSlug, []ids.RoleID{roleID}, []ids.RoleID{roleID}))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/*", handler.Handle)
	fwd.EXPECT().
		Forward(mock.Anything, mock.MatchedBy(func(in appproxy.ForwardInput) bool {
			return in.Consumer != nil && in.Consumer.Consumer != nil && in.Consumer.Consumer.RoutingMode == domainconsumer.RoutingModeRoleBased
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

func TestHandle_OAuth2ClientInlineSucceeds(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStubOAuth2Client(ids.New[ids.GatewayKind](), consumerSlug))
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

func TestHandle_Forbidden_IDPLacksRole(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStubRoleBased(ids.New[ids.GatewayKind](), consumerSlug, []ids.RoleID{ids.New[ids.RoleKind]()}, []ids.RoleID{ids.New[ids.RoleKind]()}))
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
