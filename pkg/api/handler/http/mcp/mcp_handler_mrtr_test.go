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
	"sync"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	mrtrClientMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}`
	mrtrUpstreamInputRequired = `{"resultType":"input_required","requestState":"upstream-state-1",` +
		`"inputRequests":{"q1":{"method":"elicitation/create"}}}`
)

type mrtrOutcomeRecord struct {
	outcome mcphttp.MRTROutcome
	era     string
	round   string
}

type fakeMRTRRecorder struct {
	mu      sync.Mutex
	records []mrtrOutcomeRecord
}

func (r *fakeMRTRRecorder) Record(_ context.Context, outcome mcphttp.MRTROutcome, era, round string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, mrtrOutcomeRecord{outcome: outcome, era: era, round: round})
}

func (r *fakeMRTRRecorder) all() []mrtrOutcomeRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]mrtrOutcomeRecord(nil), r.records...)
}

// fakeMRTRUpstream answers the queued results in order, so a two-round exchange
// can be driven without a real MCP server.
type fakeMRTRUpstream struct {
	mu      sync.Mutex
	results []string
	calls   []appmcp.ToolCall
}

func (u *fakeMRTRUpstream) ListTools(context.Context) ([]appmcp.Tool, error) {
	return []appmcp.Tool{{Name: "search"}}, nil
}

func (u *fakeMRTRUpstream) CallTool(_ context.Context, call appmcp.ToolCall) (json.RawMessage, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls = append(u.calls, call)
	result := u.results[0]
	if len(u.results) > 1 {
		u.results = u.results[1:]
	}
	return json.RawMessage(result), nil
}

func (u *fakeMRTRUpstream) ListResources(context.Context) ([]appmcp.Resource, error) { return nil, nil }

func (u *fakeMRTRUpstream) ListResourceTemplates(context.Context) ([]appmcp.ResourceTemplate, error) {
	return nil, nil
}

func (u *fakeMRTRUpstream) ReadResource(context.Context, string) (json.RawMessage, error) {
	return nil, appmcp.ErrNotSupported
}

func (u *fakeMRTRUpstream) ListPrompts(context.Context) ([]appmcp.Prompt, error) { return nil, nil }

func (u *fakeMRTRUpstream) GetPrompt(context.Context, string, map[string]string) (json.RawMessage, error) {
	return nil, appmcp.ErrNotSupported
}

func (u *fakeMRTRUpstream) SupportsResources() bool { return false }
func (u *fakeMRTRUpstream) SupportsPrompts() bool   { return false }
func (u *fakeMRTRUpstream) Close(context.Context)   {}

func (u *fakeMRTRUpstream) toolCalls() []appmcp.ToolCall {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]appmcp.ToolCall(nil), u.calls...)
}

type fakeMRTRDialer struct{ upstream *fakeMRTRUpstream }

func (d *fakeMRTRDialer) Connect(context.Context, appmcp.Target) (appmcp.Upstream, error) {
	return d.upstream, nil
}

type mrtrMapCache struct {
	mu sync.Mutex
	m  map[string]any
}

func (c *mrtrMapCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return v, ok
}

func (c *mrtrMapCache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = value
}

func modernMCPRegistry(t *testing.T, gatewayID ids.GatewayID) *registrydomain.Registry {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gatewayID, "github", "", &registrydomain.MCPTarget{
		URL:          "https://a.example.com/mcp",
		ProtocolMode: registrydomain.MCPProtocolModeModern,
	})
	require.NoError(t, err)
	return reg
}

// newMRTRApp wires a modern MCP consumer bound to one modern upstream, with a
// request trace so the composer's round stamp is readable at the edge.
func newMRTRApp(
	t *testing.T,
	composer appmcp.Composer,
	signer *appmcp.TicketSigner,
	recorder mcphttp.MRTRRecorder,
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
		ctx = trace.NewContext(ctx, trace.New("t-mrtr", trace.Metadata{Kind: events.KindMCP}))
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandlerWithMRTR(
		mcphttp.NewRPCGateway(composer, noopRunner(), nil),
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
		mcphttp.MRTRSupport{Signer: signer, Recorder: recorder},
	)
	app.Post(mcpPath, handler.Handle)
	return app
}

func mrtrComposer(t *testing.T, signer *appmcp.TicketSigner, results ...string) (appmcp.Composer, *fakeMRTRUpstream) {
	t.Helper()
	upstream := &fakeMRTRUpstream{results: results}
	composer := appmcp.NewComposerWithSigner(
		&fakeMRTRDialer{upstream: upstream},
		nil,
		&mrtrMapCache{m: map[string]any{}},
		discardLogger(),
		signer,
	)
	return composer, upstream
}

func mrtrResult(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	result, ok := body["result"].(map[string]any)
	require.True(t, ok, "response has no result object: %v", body)
	return result
}

// The continuation capability only appears once a secret is configured: without
// one the gateway cannot mint tickets, so advertising it would invite a
// continuation it must reject.
func TestHandler_ServerDiscover_MRTRAdvertisement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		signer *appmcp.TicketSigner
		want   map[string]any
	}{
		{
			name:   "secret configured",
			signer: appmcp.NewTicketSigner("secret", "", 0, 0),
			want:   map[string]any{"inputRequests": map[string]any{}},
		},
		{
			name:   "secret missing",
			signer: appmcp.NewTicketSigner("", "", 0, 0),
			want:   map[string]any{},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := newMRTRApp(t, mocks.NewComposer(t), tc.signer, nil)
			status, body := rpcCallWithHeaders(t, app,
				`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+mrtrClientMeta+`}}`,
				modernHeadersFor("server/discover"))

			require.Equal(t, fiber.StatusOK, status)
			capabilities := mrtrResult(t, body)["capabilities"].(map[string]any)
			require.Equal(t, tc.want, capabilities["tools"])
		})
	}
}

// A cancellation is acknowledged and forgotten: the ticket is the only
// continuation record and the client already holds it, so there is nothing to
// discard server-side.
func TestHandler_NotificationsCancelled_AcceptedAndMetered(t *testing.T) {
	t.Parallel()
	recorder := &fakeMRTRRecorder{}
	app := newMRTRApp(t, mocks.NewComposer(t), appmcp.NewTicketSigner("secret", "", 0, 0), recorder)

	status, raw := rpcRawCallWithHeaders(t, app,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1",`+mrtrClientMeta+`}}`,
		modernHeadersFor("notifications/cancelled"))

	require.Equal(t, fiber.StatusAccepted, status)
	require.Empty(t, raw)
	require.Equal(t, []mrtrOutcomeRecord{
		{outcome: mcphttp.MRTROutcomeCancelled, era: "modern", round: "1"},
	}, recorder.all())
}

// A tool that answers in one round is untouched: no continuation fields on the
// wire and a single complete outcome in telemetry.
func TestHandler_ToolsCall_OneRoundStaysUnchanged(t *testing.T) {
	t.Parallel()
	recorder := &fakeMRTRRecorder{}
	signer := appmcp.NewTicketSigner("secret", "", 0, 0)
	composer, upstream := mrtrComposer(t, signer, `{"content":[{"type":"text","text":"done"}]}`)
	app := newMRTRApp(t, composer, signer, recorder)

	status, body := rpcCallWithHeaders(t, app,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search",`+mrtrClientMeta+`}}`,
		modernHeadersWithName("tools/call", "search"))

	require.Equal(t, fiber.StatusOK, status)
	result := mrtrResult(t, body)
	require.Equal(t, "complete", result["resultType"])
	require.NotContains(t, result, "requestState")
	require.NotContains(t, result, "inputRequests")
	require.Len(t, upstream.toolCalls(), 1)
	require.Equal(t, []mrtrOutcomeRecord{
		{outcome: mcphttp.MRTROutcomeComplete, era: "modern", round: "1"},
	}, recorder.all())
}

// The full two-round exchange: the upstream asks for input, the client answers
// with the ticket the gateway minted, and the retry reaches the same upstream
// tool carrying the upstream's own state — never the ticket.
func TestHandler_ToolsCall_TwoRoundExchange(t *testing.T) {
	t.Parallel()
	recorder := &fakeMRTRRecorder{}
	signer := appmcp.NewTicketSigner("secret", "", 0, 0)
	composer, upstream := mrtrComposer(t, signer,
		mrtrUpstreamInputRequired,
		`{"resultType":"complete","content":[{"type":"text","text":"done"}]}`,
	)
	app := newMRTRApp(t, composer, signer, recorder)

	status, body := rpcCallWithHeaders(t, app,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search",`+mrtrClientMeta+`}}`,
		modernHeadersWithName("tools/call", "search"))
	require.Equal(t, fiber.StatusOK, status)
	first := mrtrResult(t, body)
	require.Equal(t, "input_required", first["resultType"])
	ticket, ok := first["requestState"].(string)
	require.True(t, ok, "the first round must carry a ticket")
	require.NotEqual(t, "upstream-state-1", ticket, "the upstream state must never reach the client")
	require.Contains(t, first["inputRequests"], "q1")

	second, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":           "search",
			"requestState":   ticket,
			"inputResponses": map[string]any{"q1": map[string]any{"action": "accept", "content": map[string]any{"city": "Madrid"}}},
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
				"io.modelcontextprotocol/clientCapabilities": map[string]any{"elicitation": map[string]any{}},
			},
		},
	})
	require.NoError(t, err)

	status, body = rpcCallWithHeaders(t, app, string(second), modernHeadersWithName("tools/call", "search"))
	require.Equal(t, fiber.StatusOK, status)
	result := mrtrResult(t, body)
	require.Equal(t, "complete", result["resultType"])
	require.NotContains(t, result, "requestState")

	calls := upstream.toolCalls()
	require.Len(t, calls, 2)
	require.Equal(t, "search", calls[1].Name)
	require.Equal(t, "upstream-state-1", calls[1].RequestState)

	require.Equal(t, []mrtrOutcomeRecord{
		{outcome: mcphttp.MRTROutcomeInputRequired, era: "modern", round: "1"},
		{outcome: mcphttp.MRTROutcomeComplete, era: "modern", round: "2"},
	}, recorder.all())
}

// A replayed or foreign ticket is rejected with its own code, and the rejection
// is metered so a spike is visible.
func TestHandler_ToolsCall_RejectedContinuationIsMetered(t *testing.T) {
	t.Parallel()
	recorder := &fakeMRTRRecorder{}
	signer := appmcp.NewTicketSigner("secret", "", 0, 0)
	composer, upstream := mrtrComposer(t, signer, `{"content":[]}`)
	app := newMRTRApp(t, composer, signer, recorder)

	status, body := rpcCallWithHeaders(t, app,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","requestState":"tg1.c.bogus.sig",`+
			mrtrClientMeta+`}}`,
		modernHeadersWithName("tools/call", "search"))

	require.Equal(t, fiber.StatusOK, status)
	rpcErr := body["error"].(map[string]any)
	require.Equal(t, float64(-32023), rpcErr["code"])
	require.Empty(t, upstream.toolCalls())
	require.Equal(t, []mrtrOutcomeRecord{
		{outcome: mcphttp.MRTROutcomeReplayRejected, era: "modern", round: "1"},
	}, recorder.all())
}

// An oversized continuation is a client mistake, not a mediation failure: it is
// rejected as invalid params before any upstream work.
func TestHandler_ToolsCall_OversizedContinuationRejected(t *testing.T) {
	t.Parallel()
	signer := appmcp.NewTicketSigner("secret", "", 0, 0)
	composer, upstream := mrtrComposer(t, signer, `{"content":[]}`)
	app := newMRTRApp(t, composer, signer, &fakeMRTRRecorder{})

	oversized := make([]byte, mcphttp.DefaultMaxContinuationBytes+1)
	for i := range oversized {
		oversized[i] = 'a'
	}
	params, err := json.Marshal(map[string]any{
		"name":           "search",
		"inputResponses": map[string]any{"q1": string(oversized)},
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
			"io.modelcontextprotocol/clientCapabilities": map[string]any{"elicitation": map[string]any{}},
		},
	})
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  json.RawMessage(params),
	})
	require.NoError(t, err)

	status, decoded := rpcCallWithHeaders(t, app, string(body), modernHeadersWithName("tools/call", "search"))
	require.Equal(t, fiber.StatusOK, status)
	rpcErr := decoded["error"].(map[string]any)
	require.Equal(t, float64(-32602), rpcErr["code"])
	require.Empty(t, upstream.toolCalls())
}

// A timed-out tool call is metered as a timeout so an upstream that stalls
// mid-exchange is distinguishable from one that refuses.
func TestHandler_ToolsCall_TimeoutIsMetered(t *testing.T) {
	t.Parallel()
	recorder := &fakeMRTRRecorder{}
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, context.DeadlineExceeded).Once()
	app := newMRTRApp(t, composer, appmcp.NewTicketSigner("secret", "", 0, 0), recorder)

	status, _ := rpcCallWithHeaders(t, app,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search",`+mrtrClientMeta+`}}`,
		modernHeadersWithName("tools/call", "search"))

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, []mrtrOutcomeRecord{
		{outcome: mcphttp.MRTROutcomeTimeout, era: "modern", round: "1"},
	}, recorder.all())
}
