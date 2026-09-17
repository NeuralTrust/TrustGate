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
	"net/http"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRPCGateway_Dispatch_RecordsToolSpan(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"content":[]}`)
	composer := mocks.NewComposer(t)
	expectToolCall(composer, "echo", raw, nil)

	rt := trace.New("t-1", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{"name":"echo"}`))
	require.NoError(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1)
	require.Equal(t, trace.SpanMCP, spans[0].Type)
	attrs, ok := spans[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "tools/call", attrs.Method)
	assert.Equal(t, "tool", attrs.Operation)
	assert.Equal(t, "echo", attrs.Tool)
	assert.Equal(t, http.StatusOK, attrs.UpstreamStatus)
}

func TestRPCGateway_Dispatch_RecordsErrorStatus(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		ListTools(mock.Anything, mock.Anything).
		Return(nil, assertErr{}).Once()

	rt := trace.New("t-2", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/list", nil)
	require.Error(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1)
	attrs, ok := spans[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "discovery", attrs.Operation)
	assert.Equal(t, http.StatusBadGateway, attrs.UpstreamStatus)
}

func TestRPCGateway_Dispatch_RecordsPolicyBlockedHTTPStatus(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	expectToolCall(composer, "echo", nil, &appmcp.RPCError{
		Code:       -32001,
		Message:    "blocked",
		HTTPStatus: http.StatusForbidden,
	})

	rt := trace.New("t-3", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{"name":"echo"}`))
	require.Error(t, err)

	attrs, ok := rt.Spans()[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, attrs.UpstreamStatus)
	assert.Equal(t, -32001, attrs.RPCErrorCode)
}

// The wire answers 200 so MCP clients parse the error, but telemetry must still
// say what the refusal means: an upstream the user has not connected is an
// authorization gap, not a broken gateway. Recording it as 502 hid real
// upstream failures among routine consent prompts.
func TestRPCGateway_Dispatch_RecordsUnknownMethodAsNotFound(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil)
	rt := trace.New("t-method", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/subscribe", nil)
	require.ErrorIs(t, err, mcphttp.ErrMethodNotFound)

	attrs, ok := rt.Spans()[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, http.StatusNotFound, attrs.UpstreamStatus)
	assert.Equal(t, -32601, attrs.RPCErrorCode)
}

func TestRPCGateway_Dispatch_RecordsConsentAsForbidden(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		Resolve(mock.Anything, mock.Anything, "notion-search").
		Return(nil, &appmcp.ConsentRequiredError{
			Provider: "com.notion/mcp", Ticket: "tk", Path: "/p/mcp",
		}).Once()

	rt := trace.New("t-4", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/call",
		json.RawMessage(`{"name":"notion-search"}`))
	require.Error(t, err)

	attrs, ok := rt.Spans()[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, attrs.UpstreamStatus)
	assert.Equal(t, -32003, attrs.RPCErrorCode)
}

type assertErr struct{}

func (assertErr) Error() string { return "boom" }

func mcpSpanAttrs(t *testing.T, rt *trace.RequestTrace) trace.MCPAttrs {
	t.Helper()
	for _, span := range rt.Spans() {
		if span.Type != trace.SpanMCP {
			continue
		}
		attrs, ok := span.MCPAttrsCopy()
		require.True(t, ok)
		return attrs
	}
	require.FailNow(t, "no MCP span recorded")
	return trace.MCPAttrs{}
}

func (f *scopeFixture) policyID(t *testing.T, name string) string {
	t.Helper()
	for _, pol := range f.rc.ScopedPolicies {
		if pol.Name == name {
			return pol.ID.String()
		}
	}
	require.FailNow(t, "no scoped policy named "+name)
	return ""
}

func marketingPrincipal() *identity.Principal {
	return &identity.Principal{
		Subject: "usr_marketing",
		Method:  identity.MethodExternalJWT,
		Claims:  map[string]any{"groups": []string{"Marketing"}},
	}
}

// With a span recording, the dispatcher explains the plan it runs: Marketing
// calling search on Y gets B (registry Y) and the unscoped C; the decision
// says A stayed out because the destination is X and D because the caller is
// not Finanzas. What ran and what the span says agree.
func TestRPCGateway_ToolsCall_StampsTheScopeDecisionOnTheSpan(t *testing.T) {
	t.Parallel()
	f := newScopeFixture(t)
	y := f.registries["y"]
	target := resolvedToolOn(y, "search", "search")
	composer := mocks.NewComposer(t)
	composer.EXPECT().Resolve(mock.Anything, mock.Anything, "search").Return(target, nil).Once()
	composer.EXPECT().Invoke(mock.Anything, mock.Anything, target, mock.Anything).
		Return(json.RawMessage(`{"content":[]}`), nil).Once()

	rt := trace.New("t-scope", trace.Metadata{Kind: events.KindMCP})
	ctx := identity.WithPrincipal(trace.NewContext(context.Background(), rt), marketingPrincipal())
	runner := appmcp.NewPluginRunner(appplugins.NewExecutor(f.reg, nil), discardLogger())
	g := mcphttp.NewRPCGateway(composer, runner, nil)

	f.rec.drain()
	_, err := g.Dispatch(ctx, f.rc, "tools/call", json.RawMessage(`{"name":"search"}`))
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"B", "C", "B", "C"}, f.rec.drain(),
		"both stages run the registry plan of Y")
	attrs := mcpSpanAttrs(t, rt)
	assert.Equal(t, "tools/call", attrs.Method)
	require.NotNil(t, attrs.PolicyScope, "a resolved tools/call under a span carries the decision")
	assert.Equal(t, 3, attrs.PolicyScope.Evaluated)
	assert.Equal(t, []string{f.policyID(t, "B")}, attrs.PolicyScope.Matched)
	assert.ElementsMatch(t, []trace.MCPSkippedPolicy{
		{ID: f.policyID(t, "A"), Name: "A", Reason: string(policydomain.SkipDestination)},
		{ID: f.policyID(t, "D"), Name: "D", Reason: string(policydomain.SkipPrincipal)},
	}, attrs.PolicyScope.Skipped)
}

// A consumer with scoped policies but nothing scoped in the way still gets a
// decision, so a reader can tell "nothing applied" from "nothing was checked".
func TestRPCGateway_ToolsCall_StampsAnEmptyDecisionWhenNothingIsScoped(t *testing.T) {
	t.Parallel()
	rc := mcpRoutableConsumer()
	unscoped := []*policydomain.Policy{scopedPolicy("C", "plugin-c", nil)}
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(&recordingPlugin{name: "plugin-c", rec: &stageRecorder{}}))
	rc.Policies = unscoped
	rc.MCPPlans = appconsumer.BuildPolicyPlans(reg, unscoped, nil, discardLogger())

	composer := mocks.NewComposer(t)
	expectToolCall(composer, "echo", json.RawMessage(`{"content":[]}`), nil)
	rt := trace.New("t-scope-empty", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, rc, "tools/call", json.RawMessage(`{"name":"echo"}`))
	require.NoError(t, err)

	attrs := mcpSpanAttrs(t, rt)
	require.NotNil(t, attrs.PolicyScope)
	assert.Equal(t, trace.MCPPolicyScope{}, *attrs.PolicyScope)
}

// The decision exists only for a tools/call bound to an upstream. Discovery,
// a gateway meta-tool, a name Resolve rejects and a consumer that never got
// precompiled plans leave the span without one.
func TestRPCGateway_Dispatch_NoScopeDecisionOutsideResolvedToolCalls(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		params json.RawMessage
		setup  func(t *testing.T) (*mcphttp.RPCGateway, *appconsumer.RoutableConsumer)
	}{
		{
			name: "consumer without MCP plans", method: "tools/call", params: json.RawMessage(`{"name":"echo"}`),
			setup: func(t *testing.T) (*mcphttp.RPCGateway, *appconsumer.RoutableConsumer) {
				composer := mocks.NewComposer(t)
				expectToolCall(composer, "echo", json.RawMessage(`{"content":[]}`), nil)
				return mcphttp.NewRPCGateway(composer, noopRunner(), nil), mcpRoutableConsumer()
			},
		},
		{
			name: "resolve fails", method: "tools/call", params: json.RawMessage(`{"name":"ghost"}`),
			setup: func(t *testing.T) (*mcphttp.RPCGateway, *appconsumer.RoutableConsumer) {
				composer := mocks.NewComposer(t)
				composer.EXPECT().Resolve(mock.Anything, mock.Anything, "ghost").
					Return(nil, appmcp.ErrToolNotFound).Once()
				return mcphttp.NewRPCGateway(composer, noopRunner(), nil), newScopeFixture(t).rc
			},
		},
		{
			name: "discovery", method: "tools/list", params: nil,
			setup: func(t *testing.T) (*mcphttp.RPCGateway, *appconsumer.RoutableConsumer) {
				composer := mocks.NewComposer(t)
				composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()
				return mcphttp.NewRPCGateway(composer, noopRunner(), nil), newScopeFixture(t).rc
			},
		},
		{
			name: "meta-tool", method: "tools/call", params: json.RawMessage(`{"name":"` + appmcp.InventoryToolName + `"}`),
			setup: func(t *testing.T) (*mcphttp.RPCGateway, *appconsumer.RoutableConsumer) {
				composer := mocks.NewComposer(t)
				composer.EXPECT().ToolInventory(mock.Anything, mock.Anything).Return(&appmcp.ToolInventory{}, nil).Once()
				inventory, err := appmcp.NewInventoryTool(composer, nil)
				require.NoError(t, err)
				return mcphttp.NewRPCGateway(composer, noopRunner(), nil).WithInventoryTool(inventory), newScopeFixture(t).rc
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g, rc := tc.setup(t)
			rt := trace.New("t-no-scope", trace.Metadata{Kind: events.KindMCP})
			ctx := trace.NewContext(context.Background(), rt)

			_, _ = g.Dispatch(ctx, rc, tc.method, tc.params)

			attrs := mcpSpanAttrs(t, rt)
			assert.Nil(t, attrs.PolicyScope, "%s must not carry a scope decision", tc.name)
		})
	}
}
