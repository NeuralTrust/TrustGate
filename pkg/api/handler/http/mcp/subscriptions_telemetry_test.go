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
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// telemetryLabels is one recorded label set, so a test can assert on the labels
// themselves rather than on an aggregate that has already lost them.
type telemetryLabels struct {
	Kind    string
	Outcome string
	Era     string
}

type listenTelemetry struct {
	mu       sync.Mutex
	samples  []telemetryLabels
	liveDelt []int64
	liveEras []string
}

func (l *listenTelemetry) Record(_ context.Context, kind, outcome, era string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.samples = append(l.samples, telemetryLabels{Kind: kind, Outcome: outcome, Era: era})
}

func (l *listenTelemetry) Live(_ context.Context, delta int64, era string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.liveDelt = append(l.liveDelt, delta)
	l.liveEras = append(l.liveEras, era)
}

func (l *listenTelemetry) recorded() []telemetryLabels {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]telemetryLabels(nil), l.samples...)
}

func (l *listenTelemetry) live() (deltas []int64, eras []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]int64(nil), l.liveDelt...), append([]string(nil), l.liveEras...)
}

// listenTelemetryApp is a listen-capable app whose telemetry surfaces are all
// observable: the recorder, the request trace, and the streamed-response metrics
// finalizer the writer is expected to invoke with no body.
type listenTelemetryApp struct {
	app         *fiber.App
	recorder    *listenTelemetry
	trace       *trace.RequestTrace
	subs        mcphttp.SubscriptionsSupport
	finalizerMu sync.Mutex
	finalized   int
	body        []byte
}

func (a *listenTelemetryApp) finalizer() infracontext.StreamMetricsFinalizer {
	return func(_ *infracontext.RequestContext, output []byte, _ int, _ map[string][]string) {
		a.finalizerMu.Lock()
		defer a.finalizerMu.Unlock()
		a.finalized++
		a.body = output
	}
}

func (a *listenTelemetryApp) finalizerCalls() (int, []byte) {
	a.finalizerMu.Lock()
	defer a.finalizerMu.Unlock()
	return a.finalized, a.body
}

// newListenTelemetryApp wires a modern MCP consumer whose listen reaches the
// lease, with a real role scoper and the one rate-limit check an open is charged.
func newListenTelemetryApp(t *testing.T, subs mcphttp.SubscriptionsSupport) *listenTelemetryApp {
	t.Helper()
	recorder := &listenTelemetry{}
	subs.Recorder = recorder
	harness := &listenTelemetryApp{
		recorder: recorder,
		trace:    trace.New("t-subscriptions-telemetry", trace.Metadata{Kind: events.KindMCP}),
		subs:     subs,
	}

	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(nil).Maybe()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{}, nil).Maybe()
	executor := pluginmocks.NewExecutor(t)
	executor.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, nil).Maybe()

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
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: cons, Registries: []*registrydomain.Registry{modernMCPRegistry(t, gwID)}},
	})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = trace.NewContext(ctx, harness.trace)
		c.SetUserContext(ctx)
		c.Locals(infracontext.StreamMetricsFinalizerKey, harness.finalizer())
		return c.Next()
	})
	handler := mcphttp.NewHandlerWithSubscriptions(
		mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(executor, discardLogger()), limiter),
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
		mcphttp.MRTRSupport{},
		mcphttp.TasksSupport{},
		subs,
	)
	app.Post(mcpPath, handler.Handle)
	harness.app = app
	return harness
}

// mcpSpanStrings is every string a span carries, so a test can search the whole
// attribute surface instead of naming the fields it happens to remember.
func mcpSpanStrings(t *testing.T, requestTrace *trace.RequestTrace) []string {
	t.Helper()
	var found []string
	for _, span := range requestTrace.Spans() {
		attrs, ok := span.MCPAttrsCopy()
		if !ok {
			continue
		}
		encoded, err := json.Marshal(attrs)
		require.NoError(t, err)
		found = append(found, string(encoded))
	}
	require.NotEmpty(t, found, "a listen must produce at least one MCP span")
	return found
}

// A whole lease reports exactly two bounded samples — the open and the close —
// and leaves the live-stream counter back where it started.
func TestHandler_SubscriptionsListen_RecordsBoundedLifecycle(t *testing.T) {
	t.Parallel()
	harness := newListenTelemetryApp(t, streamingSubscriptions(t))

	status, _, raw := listenStream(
		t,
		harness.app,
		listenRequest(`"notifications":["toolsListChanged"]`),
		listenHeaders(),
	)

	require.Equal(t, fiber.StatusOK, status)
	require.Len(t, sseFrames(t, raw), 2)
	require.Equal(
		t,
		[]telemetryLabels{
			{Outcome: trace.SubscriptionOutcomeOpened, Era: trace.MCPProtocolEraModern},
			{Outcome: trace.SubscriptionOutcomeDeadline, Era: trace.MCPProtocolEraModern},
		},
		harness.recorder.recorded(),
		"a lease that emitted nothing carries no kind label",
	)

	deltas, eras := harness.recorder.live()
	require.Equal(t, []int64{1, -1}, deltas, "live must return to zero on every termination path")
	require.Equal(t, []string{trace.MCPProtocolEraModern, trace.MCPProtocolEraModern}, eras)
	require.Zero(t, harness.subs.Registry.Live())
}

// A capacity refusal is counted as a refusal and nothing else: it opened no
// stream, so it must not move the live counter.
func TestHandler_SubscriptionsListen_RefusalRecordsOneBoundedSample(t *testing.T) {
	t.Parallel()
	subs := enabledSubscriptions(t)
	subs.Registry = appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{MaxStreams: 1})
	occupant, err := subs.Registry.Claim(context.Background(), appmcp.IsolationKey{ConsumerID: "other"})
	require.NoError(t, err)
	t.Cleanup(occupant.Release)

	harness := newListenTelemetryApp(t, subs)
	_, _, raw := listenStream(
		t,
		harness.app,
		listenRequest(`"notifications":["toolsListChanged"]`),
		listenHeaders(),
	)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, float64(-32026), rpcErrorObject(t, decoded)["code"])
	require.Equal(
		t,
		[]telemetryLabels{{Outcome: trace.SubscriptionOutcomeRefused, Era: trace.MCPProtocolEraModern}},
		harness.recorder.recorded(),
	)
	deltas, _ := harness.recorder.live()
	require.Empty(t, deltas, "a refused listen never claimed a slot")
}

// The requirement is a negative one, so the assertion is a search: nothing the
// client sent — the subscription id, the JSON-RPC id, a requested resource URI —
// may appear anywhere on the span, and the outcome label must be enumerated.
func TestHandler_SubscriptionsListen_SpanCarriesNoClientContent(t *testing.T) {
	t.Parallel()
	harness := newListenTelemetryApp(t, streamingSubscriptions(t))

	uris := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		uris = append(uris, `"doc://tenant-secret/`+strconv.Itoa(i)+`"`)
	}
	_, _, raw := listenStream(
		t,
		harness.app,
		listenRequest(`"notifications":["toolsListChanged"],"resourceSubscriptions":[`+strings.Join(uris, ",")+`]`),
		listenHeaders(),
	)
	require.Len(t, sseFrames(t, raw), 2)

	for _, encoded := range mcpSpanStrings(t, harness.trace) {
		require.NotContains(t, encoded, "doc://", "a requested resource URI must never be an attribute")
		require.NotContains(t, encoded, "tenant-secret")
		require.NotContains(t, encoded, "toolsListChanged", "the honoured subset is not a span attribute")
	}

	for _, span := range harness.trace.Spans() {
		attrs, ok := span.MCPAttrsCopy()
		if !ok || attrs.Method != appmcp.MethodSubscriptionsListen {
			continue
		}
		require.Equal(t, trace.SubscriptionOutcomeOpened, attrs.SubscriptionOutcome)
		require.Empty(t, attrs.SubscriptionKind)
		require.Empty(t, attrs.ResourceURI)
		require.Empty(t, attrs.Tool)
		require.Empty(t, attrs.Prompt)
		return
	}
	t.Fatal("no listen span was recorded")
}

// The stream finalizer is the one place a response body could have been captured,
// so it must be invoked exactly once and with nothing to capture.
func TestHandler_SubscriptionsListen_MetricsFinalizerCarriesNoBody(t *testing.T) {
	t.Parallel()
	harness := newListenTelemetryApp(t, streamingSubscriptions(t))

	_, _, raw := listenStream(
		t,
		harness.app,
		listenRequest(`"notifications":["toolsListChanged"]`),
		listenHeaders(),
	)
	require.Len(t, sseFrames(t, raw), 2)

	calls, body := harness.finalizerCalls()
	require.Equal(t, 1, calls, "a claimed stream emits exactly once, at close")
	require.Nil(t, body, "no frame may be captured for telemetry")
}
