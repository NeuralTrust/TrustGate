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

package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	subscriptionsMaxURIs       = 32
	subscriptionsMaxEventBytes = 8192
	subscriptionsMaxLifetime   = time.Minute
	subscriptionsCap           = 8

	// subscriptionsStreamLifetime is short enough to observe a whole lease from
	// the ack to the terminal frame. Its tickers stay at subscriptionsMaxLifetime,
	// so a drained stream is exactly those two frames.
	subscriptionsStreamLifetime = 40 * time.Millisecond
)

// subscriptionsSpies are the collaborators a listen must not touch when it is
// refused at the protocol boundary.
type subscriptionsSpies struct {
	limiter  *ratelimitmocks.Checker
	composer *mocks.Composer
	executor *pluginmocks.Executor
	scoper   *mocks.RoleScoper
}

func (s subscriptionsSpies) requireUntouched(t *testing.T) {
	t.Helper()
	require.Empty(t, s.limiter.Calls, "a boundary refusal must not check the rate limit")
	require.Empty(t, s.composer.Calls, "a boundary refusal must not reach the composer")
	require.Empty(t, s.executor.Calls, "a boundary refusal must not run a plugin")
	require.Empty(t, s.scoper.Calls, "a boundary refusal must not resolve role scope")
}

// enabledSubscriptions is the feature on with a policy that must never be
// consulted: its tick is longer than any lifetime a test drains.
func enabledSubscriptions(t *testing.T) mcphttp.SubscriptionsSupport {
	t.Helper()
	return mcphttp.SubscriptionsSupport{
		On:             true,
		MaxLifetime:    subscriptionsMaxLifetime,
		ReauthInterval: subscriptionsMaxLifetime,
		Keepalive:      subscriptionsMaxLifetime,
		MaxEventBytes:  subscriptionsMaxEventBytes,
		MaxURIs:        subscriptionsMaxURIs,
		Registry: appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{
			MaxStreams:      subscriptionsCap,
			MaxPerConsumer:  subscriptionsCap,
			MaxPerPrincipal: subscriptionsCap,
		}),
		Policy: mocks.NewSubscriptionPolicy(t),
	}
}

// streamingSubscriptions is the same feature with a lease that reaches its
// deadline while the test is still running.
func streamingSubscriptions(t *testing.T) mcphttp.SubscriptionsSupport {
	t.Helper()
	subs := enabledSubscriptions(t)
	subs.MaxLifetime = subscriptionsStreamLifetime
	return subs
}

// sseFrames splits an event-stream body into its frames, so a test asserts on
// what a client scanner would see rather than on one opaque blob.
func sseFrames(t *testing.T, raw []byte) []string {
	t.Helper()
	frames := make([]string, 0, 2)
	for _, frame := range strings.Split(strings.TrimSuffix(string(raw), "\n\n"), "\n\n") {
		if frame != "" {
			frames = append(frames, frame)
		}
	}
	return frames
}

// sseFrameData decodes the JSON payload of one `event: message` frame.
func sseFrameData(t *testing.T, frame string) map[string]any {
	t.Helper()
	require.True(t, strings.HasPrefix(frame, "event: message\ndata: "), "unexpected frame %q", frame)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(frame, "event: message\ndata: ")), &decoded))
	return decoded
}

// newSubscriptionsApp wires a modern MCP consumer with mocked collaborators, so a
// refusal that touches any of them fails the test rather than passing silently.
func newSubscriptionsApp(
	t *testing.T,
	subs mcphttp.SubscriptionsSupport,
) (*fiber.App, subscriptionsSpies) {
	t.Helper()
	spies := subscriptionsSpies{
		limiter:  ratelimitmocks.NewChecker(t),
		composer: mocks.NewComposer(t),
		executor: pluginmocks.NewExecutor(t),
		scoper:   mocks.NewRoleScoper(t),
	}
	app := newSubscriptionsAppWith(t, subs, spies, spies.scoper)
	return app, spies
}

func newSubscriptionsAppWith(
	t *testing.T,
	subs mcphttp.SubscriptionsSupport,
	spies subscriptionsSpies,
	scoper appmcp.RoleScoper,
) *fiber.App {
	t.Helper()
	return newSubscriptionsAppWithTrace(
		t,
		subs,
		spies,
		scoper,
		trace.New("t-subscriptions", trace.Metadata{Kind: events.KindMCP}),
	)
}

func newSubscriptionsAppWithTrace(
	t *testing.T,
	subs mcphttp.SubscriptionsSupport,
	spies subscriptionsSpies,
	scoper appmcp.RoleScoper,
	requestTrace *trace.RequestTrace,
) *fiber.App {
	t.Helper()
	authID := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "virtual",
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
		AuthIDs:   []ids.AuthID{authID},
	}
	registries := []*registrydomain.Registry{modernMCPRegistry(t, gwID)}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: cons, Registries: registries},
	})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = trace.NewContext(ctx, requestTrace)
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandlerWithSubscriptions(
		mcphttp.NewRPCGateway(spies.composer, appmcp.NewPluginRunner(spies.executor, discardLogger()), spies.limiter),
		scoper,
		mcphttp.MRTRSupport{},
		mcphttp.TasksSupport{},
		subs,
	)
	app.Post(mcpPath, handler.Handle)
	app.Get(mcpPath, handler.MethodNotAllowed)
	app.Delete(mcpPath, handler.MethodNotAllowed)
	return app
}

func listenHeaders() http.Header {
	headers := modernHeadersFor(appmcp.MethodSubscriptionsListen)
	headers.Set(fiber.HeaderAccept, "text/event-stream, application/json")
	return headers
}

func listenRequest(params string) string {
	return `{"jsonrpc":"2.0","id":7,"method":"` + appmcp.MethodSubscriptionsListen + `","params":{` +
		params + `,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{}}}}`
}

func uriList(count int) string {
	uris := make([]string, 0, count)
	for i := 0; i < count; i++ {
		uris = append(uris, `"doc://`+strconv.Itoa(i)+`"`)
	}
	return `"resourceSubscriptions":[` + strings.Join(uris, ",") + `]`
}

func TestHandler_SubscriptionsListen_HeaderNegotiationRefusedAtTheBoundary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(http.Header)
		wantErr string
	}{
		{
			name:    "Accept absent",
			mutate:  func(h http.Header) { h.Del(fiber.HeaderAccept) },
			wantErr: "Accept",
		},
		{
			name:    "Accept omits the event stream",
			mutate:  func(h http.Header) { h.Set(fiber.HeaderAccept, "application/json") },
			wantErr: "Accept",
		},
		{
			name:    "Accept omits the JSON payload",
			mutate:  func(h http.Header) { h.Set(fiber.HeaderAccept, "text/event-stream") },
			wantErr: "Accept",
		},
		{
			name:    "a wildcard is not enough",
			mutate:  func(h http.Header) { h.Set(fiber.HeaderAccept, "*/*") },
			wantErr: "Accept",
		},
		{
			name:    "Mcp-Name is not supported on a lease",
			mutate:  func(h http.Header) { h.Set("Mcp-Name", "toolsListChanged") },
			wantErr: "Mcp-Name",
		},
		{
			name:    "Mcp-Param-* is not supported on a lease",
			mutate:  func(h http.Header) { h.Set("Mcp-Param-Cursor", "1") },
			wantErr: "Mcp-Param",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app, spies := newSubscriptionsApp(t, enabledSubscriptions(t))
			headers := listenHeaders()
			tc.mutate(headers)

			status, body := rpcCallWithHeaders(t, app, listenRequest(`"notifications":["toolsListChanged"]`), headers)

			require.Equal(t, fiber.StatusBadRequest, status)
			rpcErr := rpcErrorObject(t, body)
			require.Equal(t, float64(-32020), rpcErr["code"])
			require.Contains(t, rpcErr["message"], tc.wantErr)
			spies.requireUntouched(t)
		})
	}
}

func TestHandler_SubscriptionsListen_ParamsRefusedAtTheBoundary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		params string
	}{
		{name: "notifications missing", params: `"unrelated":true`},
		{name: "notifications is not an array", params: `"notifications":{"toolsListChanged":true}`},
		{name: "notifications carries a non-string", params: `"notifications":[1]`},
		{
			name:   "notifications exceeds the supported-kind cap",
			params: `"notifications":["toolsListChanged","promptsListChanged","resourcesListChanged","unknown"]`,
		},
		{
			name:   "resourceSubscriptions is not an array",
			params: `"notifications":["toolsListChanged"],"resourceSubscriptions":"doc://a"`,
		},
		{
			name:   "resourceSubscriptions carries an empty URI",
			params: `"notifications":["toolsListChanged"],"resourceSubscriptions":["",""]`,
		},
		{
			name:   "resourceSubscriptions exceeds the maximum",
			params: `"notifications":["toolsListChanged"],` + uriList(subscriptionsMaxURIs+1),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app, spies := newSubscriptionsApp(t, enabledSubscriptions(t))

			status, body := rpcCallWithHeaders(t, app, listenRequest(tc.params), listenHeaders())

			require.Equal(t, fiber.StatusBadRequest, status)
			require.Equal(t, float64(-32602), rpcErrorObject(t, body)["code"])
			spies.requireUntouched(t)
		})
	}
}

// The bound is on cardinality, not on the request: exactly MaxURIs entries are
// accepted, parsed, and then discarded without ever being honoured.
func TestHandler_SubscriptionsListen_MaximumURIsAccepted(t *testing.T) {
	t.Parallel()
	app := newScopedSubscriptionsApp(t, streamingSubscriptions(t))

	params := `"notifications":["toolsListChanged"],` + uriList(subscriptionsMaxURIs)
	status, header, raw := listenStream(t, app, listenRequest(params), listenHeaders())

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, "text/event-stream", header.Get(fiber.HeaderContentType))
	frames := sseFrames(t, raw)
	require.Len(t, frames, 2)
	require.Equal(
		t,
		[]any{"toolsListChanged"},
		sseFrameData(t, frames[1])["result"].(map[string]any)["notifications"],
		"the URIs are accepted, bounded and then discarded: only the requested kind is honoured",
	)
}

// The transport must add no surface of its own: an SSE lease carries the stream
// headers a proxy needs and still no session header.
func TestHandler_SubscriptionsListen_StreamHeaders(t *testing.T) {
	t.Parallel()
	app := newScopedSubscriptionsApp(t, streamingSubscriptions(t))

	status, header, raw := listenStream(
		t,
		app,
		listenRequest(`"notifications":["toolsListChanged"]`),
		listenHeaders(),
	)

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, "text/event-stream", header.Get(fiber.HeaderContentType))
	require.Equal(t, "no-cache, no-transform", header.Get(fiber.HeaderCacheControl))
	require.Equal(t, "no", header.Get("X-Accel-Buffering"))
	require.Empty(t, header.Get("Mcp-Session-Id"), "a lease must not mint a session")
	require.NotEmpty(t, sseFrames(t, raw))
}

// The ack is the first frame a client sees and it is a notification, so it
// carries no result envelope and no id of its own.
func TestHandler_SubscriptionsListen_AckIsTheFirstFrame(t *testing.T) {
	t.Parallel()
	app := newScopedSubscriptionsApp(t, streamingSubscriptions(t))

	_, _, raw := listenStream(t, app, listenRequest(`"notifications":["toolsListChanged"]`), listenHeaders())

	frames := sseFrames(t, raw)
	require.Len(t, frames, 2)
	ack := sseFrameData(t, frames[0])
	require.Equal(t, "notifications/subscriptions/acknowledged", ack["method"])
	require.Nil(t, ack["id"])
	require.Nil(t, ack["result"])
	params, ok := ack["params"].(map[string]any)
	require.True(t, ok, "ack carries no params: %v", ack)
	require.Equal(t, []any{"toolsListChanged"}, params["notifications"])
	require.Equal(
		t,
		float64(7),
		params["_meta"].(map[string]any)["io.modelcontextprotocol/subscriptionId"],
	)
}

// A capacity refusal happens before any byte is written, so the client sees an
// ordinary buffered JSON-RPC error and no stream ever existed.
func TestHandler_SubscriptionsListen_RefusedAtCapacity(t *testing.T) {
	t.Parallel()
	subs := enabledSubscriptions(t)
	subs.Registry = appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{MaxStreams: 1})
	occupant, err := subs.Registry.Claim(context.Background(), appmcp.IsolationKey{ConsumerID: "other"})
	require.NoError(t, err)
	t.Cleanup(occupant.Release)

	app := newScopedSubscriptionsApp(t, subs)
	status, header, raw := listenStream(
		t,
		app,
		listenRequest(`"notifications":["toolsListChanged"]`),
		listenHeaders(),
	)

	require.Equal(t, fiber.StatusOK, status)
	require.NotEqual(t, "text/event-stream", header.Get(fiber.HeaderContentType))
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	rpcErr := rpcErrorObject(t, decoded)
	require.Equal(t, float64(-32026), rpcErr["code"])
	require.Nil(t, rpcErr["data"], "a refusal must not disclose which cap was reached")
	require.Equal(t, 1, subs.Registry.Live(), "a refusal must not disturb a live stream")
}

// newScopedSubscriptionsApp wires a listen that reaches the lease, which needs a
// real role scoper and one rate-limit check.
func newScopedSubscriptionsApp(t *testing.T, subs mcphttp.SubscriptionsSupport) *fiber.App {
	t.Helper()
	spies := subscriptionsSpies{
		limiter:  ratelimitmocks.NewChecker(t),
		composer: mocks.NewComposer(t),
		executor: pluginmocks.NewExecutor(t),
		scoper:   mocks.NewRoleScoper(t),
	}
	spies.limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(nil).Once()
	allowToolsAdmission(spies)
	return newSubscriptionsAppWith(t, subs, spies, appmcp.NewRoleScoper(approle.NewOIDCResolver()))
}

func allowToolsAdmission(spies subscriptionsSpies) {
	spies.composer.EXPECT().
		ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{}, nil).
		Maybe()
	spies.executor.EXPECT().
		RunStage(mock.Anything, mock.Anything).
		Return(&appplugins.StageOutcome{}, nil).
		Maybe()
}

// listenStream drains the whole response, so an event-stream body is observed as
// the frames a client scanner would read.
func listenStream(t *testing.T, app *fiber.App, body string, headers http.Header) (int, http.Header, []byte) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, mcpPath, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	res, err := app.Test(req, -1)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, res.Header, raw
}

// The kill switch must restore the pre-subscriptions wire exactly: an unknown
// method, not a validation failure, whatever headers or params the client sends.
func TestHandler_SubscriptionsListen_DisabledRestoresPriorBehaviour(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		headers func() http.Header
		params  string
	}{
		{name: "a well-formed listen", headers: listenHeaders, params: `"notifications":["toolsListChanged"]`},
		{
			name:    "a listen whose Accept would be refused when enabled",
			headers: func() http.Header { return modernHeadersFor(appmcp.MethodSubscriptionsListen) },
			params:  `"notifications":["toolsListChanged"]`,
		},
		{
			name: "a listen carrying Mcp-Name",
			headers: func() http.Header {
				return modernHeadersWithName(appmcp.MethodSubscriptionsListen, "toolsListChanged")
			},
			params: `"notifications":["toolsListChanged"]`,
		},
		{name: "a listen with no notifications at all", headers: listenHeaders, params: `"unrelated":true`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app, spies := newSubscriptionsApp(t, mcphttp.SubscriptionsSupport{})

			status, raw := rpcRawCallWithHeaders(t, app, listenRequest(tc.params), tc.headers())

			require.Equal(t, fiber.StatusNotFound, status)
			unknownStatus, unknownRaw := rpcRawCallWithHeaders(
				t,
				app,
				strings.ReplaceAll(listenRequest(tc.params), appmcp.MethodSubscriptionsListen, "unknown/method"),
				unknownMethodHeaders(tc.headers()),
			)
			require.Equal(t, unknownStatus, status)
			require.Equal(t, string(unknownRaw), string(raw), "a disabled listen must be an ordinary unknown method")
			spies.requireUntouched(t)
		})
	}
}

// Discovery advertises the lease only when one could actually be served, and it
// never grows a resources.subscribe: TrustGate honours no per-URI subscription.
func TestHandler_ServerDiscover_AdvertisesListChanged(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		subs func(*testing.T) mcphttp.SubscriptionsSupport
		want map[string]any
	}{
		{
			name: "enabled",
			subs: enabledSubscriptions,
			want: map[string]any{
				"tools":     map[string]any{"listChanged": true},
				"prompts":   map[string]any{"listChanged": true},
				"resources": map[string]any{"listChanged": true},
			},
		},
		{
			name: "disabled",
			subs: func(*testing.T) mcphttp.SubscriptionsSupport { return mcphttp.SubscriptionsSupport{} },
			want: map[string]any{
				"tools":     map[string]any{},
				"prompts":   map[string]any{},
				"resources": map[string]any{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app, spies := newSubscriptionsApp(t, tc.subs(t))

			status, body := rpcCallWithHeaders(
				t,
				app,
				`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+
					`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",`+
					`"io.modelcontextprotocol/clientCapabilities":{}}}}`,
				modernHeadersFor("server/discover"),
			)

			require.Equal(t, fiber.StatusOK, status)
			require.Equal(t, tc.want, mrtrResult(t, body)["capabilities"])
			spies.requireUntouched(t)
		})
	}
}

// A legacy initialize must stay exactly as it was: the lease is modern-only, so
// the legacy advertisement neither gains listChanged nor learns about subscribe.
func TestHandler_LegacyInitialize_NeverAdvertisesListChanged(t *testing.T) {
	t.Parallel()
	app, spies := newSubscriptionsApp(t, enabledSubscriptions(t))

	status, body := rpcCall(
		t,
		app,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
	)

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, map[string]any{
		"tools":     map[string]any{"listChanged": false},
		"resources": map[string]any{"subscribe": false, "listChanged": false},
		"prompts":   map[string]any{"listChanged": false},
	}, mrtrResult(t, body)["capabilities"])
	spies.requireUntouched(t)
}

func unknownMethodHeaders(headers http.Header) http.Header {
	out := headers.Clone()
	out.Set("Mcp-Method", "unknown/method")
	return out
}

// Non-POST verbs are transport-level and must keep answering 405 with Allow: POST
// whether the feature is on or off.
func TestHandler_SubscriptionsListen_NonPostUnchanged(t *testing.T) {
	t.Parallel()
	for _, subs := range []mcphttp.SubscriptionsSupport{{}, enabledSubscriptions(t)} {
		subs := subs
		t.Run(strconv.FormatBool(subs.Enabled()), func(t *testing.T) {
			t.Parallel()
			app, _ := newSubscriptionsApp(t, subs)
			for _, method := range []string{fiber.MethodGet, fiber.MethodDelete} {
				res, err := app.Test(httptest.NewRequest(method, mcpPath, nil), -1)
				require.NoError(t, err)
				require.NoError(t, res.Body.Close())
				require.Equal(t, fiber.StatusMethodNotAllowed, res.StatusCode)
				require.Equal(t, fiber.MethodPost, res.Header.Get(fiber.HeaderAllow))
			}
		})
	}
}

// A legacy-era listen is not a subscription at all: the modern-only method falls
// through to the ordinary unknown-legacy-method path even with the feature on.
func TestHandler_SubscriptionsListen_LegacyEraUnchanged(t *testing.T) {
	t.Parallel()
	spies := subscriptionsSpies{
		limiter:  ratelimitmocks.NewChecker(t),
		composer: mocks.NewComposer(t),
		executor: pluginmocks.NewExecutor(t),
		scoper:   mocks.NewRoleScoper(t),
	}
	app := newSubscriptionsAppWith(
		t,
		enabledSubscriptions(t),
		spies,
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
	)

	status, body := rpcCall(
		t,
		app,
		`{"jsonrpc":"2.0","id":7,"method":"`+appmcp.MethodSubscriptionsListen+`","params":{}}`,
	)

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, float64(-32601), rpcErrorObject(t, body)["code"])
	require.Empty(t, spies.limiter.Calls, "an unknown legacy method is refused before the rate limit")
	require.Empty(t, spies.composer.Calls)
}

// With the feature on, a listen is dispatched: it is never method-not-found, it is
// charged exactly once at open, and it ends in the one terminal result shape.
func TestHandler_SubscriptionsListen_EnabledDispatchesTerminalResult(t *testing.T) {
	t.Parallel()
	spies := subscriptionsSpies{
		limiter:  ratelimitmocks.NewChecker(t),
		composer: mocks.NewComposer(t),
		executor: pluginmocks.NewExecutor(t),
		scoper:   mocks.NewRoleScoper(t),
	}
	spies.limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(nil).Once()
	allowToolsAdmission(spies)
	app := newSubscriptionsAppWith(
		t,
		streamingSubscriptions(t),
		spies,
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
	)

	status, _, raw := listenStream(
		t,
		app,
		listenRequest(`"notifications":["toolsListChanged","promptsListChanged","resourcesUpdated"]`),
		listenHeaders(),
	)

	require.Equal(t, fiber.StatusOK, status)
	frames := sseFrames(t, raw)
	require.Len(t, frames, 2)
	terminal := sseFrameData(t, frames[1])
	require.Nil(t, terminal["error"])
	require.Equal(t, float64(7), terminal["id"])
	result := mrtrResult(t, terminal)
	require.Equal(t, "complete", result["resultType"])
	require.Equal(t, float64(0), result["ttlMs"])
	require.Equal(t, "private", result["cacheScope"])
	require.Equal(
		t,
		[]any{"toolsListChanged", "promptsListChanged"},
		result["notifications"],
		"an unknown notification type is dropped, not refused",
	)
	metadata, ok := result["_meta"].(map[string]any)
	require.True(t, ok, "terminal result carries no _meta: %v", result)
	require.Equal(t, float64(7), metadata["io.modelcontextprotocol/subscriptionId"])
	require.Len(t, spies.limiter.Calls, 1, "a lease is charged once at open, never for its lifetime")
	require.Len(t, spies.composer.Calls, 1)
	require.Len(t, spies.executor.Calls, 1)
}

func TestHandler_SubscriptionsListen_PluginDenialCreatesNoLease(t *testing.T) {
	t.Parallel()
	subs := enabledSubscriptions(t)
	spies := subscriptionsSpies{
		limiter:  ratelimitmocks.NewChecker(t),
		composer: mocks.NewComposer(t),
		executor: pluginmocks.NewExecutor(t),
		scoper:   mocks.NewRoleScoper(t),
	}
	spies.limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(nil).Once()
	spies.composer.EXPECT().
		ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{{Name: "blocked"}}, nil).
		Once()
	spies.executor.EXPECT().
		RunStage(mock.Anything, mock.Anything).
		Return(nil, &appplugins.PluginError{StatusCode: fiber.StatusForbidden, Message: "blocked"}).
		Once()
	app := newSubscriptionsAppWith(
		t,
		subs,
		spies,
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
	)

	status, body := rpcCallWithHeaders(
		t,
		app,
		listenRequest(`"notifications":["toolsListChanged"]`),
		listenHeaders(),
	)

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, float64(-32001), rpcErrorObject(t, body)["code"])
	require.Zero(t, subs.Registry.Live())
}

// A refused rate limit is the ordinary MCP refusal: no stream, no lease.
func TestHandler_SubscriptionsListen_RateLimitRefusalIsOrdinary(t *testing.T) {
	t.Parallel()
	spies := subscriptionsSpies{
		limiter:  ratelimitmocks.NewChecker(t),
		composer: mocks.NewComposer(t),
		executor: pluginmocks.NewExecutor(t),
		scoper:   mocks.NewRoleScoper(t),
	}
	spies.limiter.EXPECT().
		Check(mock.Anything, mock.Anything).
		Return(&ratelimitapp.Exceeded{}).
		Once()
	app := newSubscriptionsAppWith(
		t,
		enabledSubscriptions(t),
		spies,
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
	)

	_, body := rpcCallWithHeaders(t, app, listenRequest(`"notifications":["toolsListChanged"]`), listenHeaders())

	require.Equal(t, float64(appmcp.CodeRateLimited), rpcErrorObject(t, body)["code"])
	require.Empty(t, spies.composer.Calls)
}

// The lease open is traced under its own span, carrying no subscription id and no
// requested URI.
func TestHandler_SubscriptionsListen_OpenIsTraced(t *testing.T) {
	t.Parallel()
	spies := subscriptionsSpies{
		limiter:  ratelimitmocks.NewChecker(t),
		composer: mocks.NewComposer(t),
		executor: pluginmocks.NewExecutor(t),
		scoper:   mocks.NewRoleScoper(t),
	}
	spies.limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(nil).Once()
	allowToolsAdmission(spies)
	requestTrace := trace.New("t-listen-span", trace.Metadata{Kind: events.KindMCP})
	app := newSubscriptionsAppWithTrace(
		t,
		streamingSubscriptions(t),
		spies,
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
		requestTrace,
	)

	status, _ := rpcCallWithHeaders(
		t,
		app,
		listenRequest(`"notifications":["toolsListChanged"]`),
		listenHeaders(),
	)
	require.Equal(t, fiber.StatusOK, status)

	require.Len(t, requestTrace.Spans(), 1)
	attrs, ok := requestTrace.Spans()[0].MCPAttrsCopy()
	require.True(t, ok)
	require.Equal(t, appmcp.MethodSubscriptionsListen, attrs.Method)
	require.Equal(t, "subscription", attrs.Operation)
	require.Empty(t, attrs.Tool)
	require.Empty(t, attrs.ResourceURI)
	require.Equal(t, "modern", attrs.ProtocolEra)
}
