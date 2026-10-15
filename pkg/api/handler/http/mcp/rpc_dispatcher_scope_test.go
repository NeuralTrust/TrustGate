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
	"errors"
	"fmt"
	"sync"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func stubRegistry(name string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Name:      name,
		Enabled:   true,
		MCPTarget: &registrydomain.MCPTarget{URL: "https://" + name + ".example.com/mcp"},
	}
}

func resolvedToolOn(reg *registrydomain.Registry, native, exposed string) *appmcp.ResolvedTool {
	return &appmcp.ResolvedTool{Registry: reg, Tool: appmcp.Tool{Name: native}, Exposed: exposed}
}

func resolvedTool(name string) *appmcp.ResolvedTool {
	return resolvedToolOn(stubRegistry("upstream"), name, name)
}

func expectResolve(composer *mocks.Composer, name string) *appmcp.ResolvedTool {
	target := resolvedTool(name)
	composer.EXPECT().Resolve(mock.Anything, mock.Anything, name).Return(target, nil).Once()
	return target
}

func expectToolCall(composer *mocks.Composer, name string, result json.RawMessage, err error) *appmcp.ResolvedTool {
	target := expectResolve(composer, name)
	composer.EXPECT().Invoke(mock.Anything, mock.Anything, target, mock.Anything).Return(result, err).Once()
	return target
}

type stageRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *stageRecorder) record(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, name)
}

func (r *stageRecorder) drain() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.seen...)
	r.seen = nil
	return out
}

type recordingPlugin struct {
	name string
	rec  *stageRecorder
}

func (p *recordingPlugin) Name() string                          { return p.name }
func (p *recordingPlugin) MandatoryStages() []policydomain.Stage { return nil }
func (p *recordingPlugin) SupportedStages() []policydomain.Stage {
	return []policydomain.Stage{policydomain.StagePreRequest, policydomain.StagePreResponse}
}
func (p *recordingPlugin) SupportedModes() []policydomain.Mode {
	return []policydomain.Mode{policydomain.ModeEnforce}
}
func (p *recordingPlugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolMCP}
}
func (p *recordingPlugin) ValidateConfig(map[string]any) error { return nil }
func (p *recordingPlugin) MutatesRequestBody() bool            { return false }
func (p *recordingPlugin) MutatesResponseBody() bool           { return false }
func (p *recordingPlugin) MutatesMetadata() bool               { return false }

func (p *recordingPlugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	p.rec.record(in.Config.Name)
	return &appplugins.Result{StatusCode: 200}, nil
}

func scopedPolicy(name, slug string, scope *policydomain.MCPScope) *policydomain.Policy {
	return &policydomain.Policy{
		ID:       ids.New[ids.PolicyKind](),
		Name:     name,
		Slug:     slug,
		Enabled:  true,
		Stages:   []policydomain.Stage{policydomain.StagePreRequest, policydomain.StagePreResponse},
		MCPScope: scope,
	}
}

// scopeFixture is a consumer with real precompiled PolicyPlans: A scoped to
// run_query on X, B scoped to registry Y, C unscoped and D scoped to Y for the
// Finanzas group. Its plugins record which policy ran, so a captured plan can
// be replayed through a real executor and read back by policy name.
type scopeFixture struct {
	rc         *appconsumer.RoutableConsumer
	reg        appplugins.Registry
	rec        *stageRecorder
	registries map[string]*registrydomain.Registry
}

func newScopeFixture(t *testing.T) *scopeFixture {
	t.Helper()
	rec := &stageRecorder{}
	reg := appplugins.NewRegistry()
	for _, slug := range []string{"plugin-a", "plugin-b", "plugin-c", "plugin-d"} {
		require.NoError(t, reg.Register(&recordingPlugin{name: slug, rec: rec}))
	}
	x, y := stubRegistry("x"), stubRegistry("y")
	unscoped := []*policydomain.Policy{scopedPolicy("C", "plugin-c", nil)}
	scoped := []*policydomain.Policy{
		scopedPolicy("A", "plugin-a", &policydomain.MCPScope{
			Tools: []policydomain.MCPToolRef{{RegistryID: x.ID, Tool: "run_query"}},
		}),
		scopedPolicy("B", "plugin-b", &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{y.ID}}),
		scopedPolicy("D", "plugin-d", &policydomain.MCPScope{
			RegistryIDs: []ids.RegistryID{y.ID},
			Groups:      []string{"Finanzas"},
		}),
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: ids.New[ids.GatewayKind](),
			Type:      consumerdomain.TypeMCP,
		},
		Policies:       unscoped,
		PolicyPlan:     appplugins.NewStagePlan(reg, unscoped, discardLogger()),
		ScopedPolicies: scoped,
		MCPPlans:       appconsumer.BuildPolicyPlans(reg, unscoped, scoped, discardLogger()),
	}
	return &scopeFixture{
		rc:         rc,
		reg:        reg,
		rec:        rec,
		registries: map[string]*registrydomain.Registry{"x": x, "y": y},
	}
}

func (f *scopeFixture) executed(t *testing.T, plan *appplugins.StagePlan) []string {
	t.Helper()
	f.rec.drain()
	_, err := appplugins.NewExecutor(f.reg, nil).RunStage(context.Background(), appplugins.StageInput{
		Stage:    policydomain.StagePreRequest,
		Plan:     plan,
		Request:  &infracontext.RequestContext{},
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	return f.rec.drain()
}

func financePrincipal() *identity.Principal {
	return &identity.Principal{
		Subject: "usr_finance",
		Method:  identity.MethodExternalJWT,
		Claims:  map[string]any{"groups": []string{"Finanzas"}},
	}
}

// The plan is chosen once, for the destination Resolve fixed, and both stages
// run exactly that plan: tool-scoped policies on their tool, registry-scoped
// ones anywhere on their registry, unscoped ones everywhere, and
// principal-scoped ones only for a matching caller. The executor sees the plan
// alone, with no consumer-wide policy list to fall back to.
func TestRPCGateway_ToolsCall_SamePlanBothStages(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		registry     string
		tool         string
		principal    *identity.Principal
		wantPolicies []string
		static       bool
	}{
		{name: "tool of X runs the tool plan", registry: "x", tool: "run_query", wantPolicies: []string{"A", "C"}, static: true},
		{name: "another tool of X runs the base plan", registry: "x", tool: "list_tables", wantPolicies: []string{"C"}, static: true},
		{name: "tool of Y runs the registry plan", registry: "y", tool: "search", wantPolicies: []string{"B", "C"}, static: true},
		{name: "Finanzas on Y adds the group-scoped policy", registry: "y", tool: "search", principal: financePrincipal(), wantPolicies: []string{"B", "C", "D"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newScopeFixture(t)
			reg := f.registries[tc.registry]
			target := resolvedToolOn(reg, tc.tool, tc.tool)
			composer := mocks.NewComposer(t)
			composer.EXPECT().Resolve(mock.Anything, mock.Anything, tc.tool).Return(target, nil).Once()
			composer.EXPECT().Invoke(mock.Anything, mock.Anything, target, mock.Anything).
				Return(json.RawMessage(`{"content":[]}`), nil).Once()

			exec := pluginmocks.NewExecutor(t)
			captured := map[policydomain.Stage]appplugins.StageInput{}
			exec.EXPECT().RunStage(mock.Anything, mock.Anything).
				Run(func(_ context.Context, in appplugins.StageInput) { captured[in.Stage] = in }).
				Return(&appplugins.StageOutcome{}, nil).Twice()

			ctx := context.Background()
			if tc.principal != nil {
				ctx = identity.WithPrincipal(ctx, tc.principal)
			}
			g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
			_, err := g.Dispatch(ctx, f.rc, "tools/call", json.RawMessage(`{"name":"`+tc.tool+`"}`))
			require.NoError(t, err)

			pre, post := captured[policydomain.StagePreRequest], captured[policydomain.StagePreResponse]
			require.NotNil(t, pre.Plan, "PreRequest must run a destination plan")
			assert.Same(t, pre.Plan, post.Plan, "PreResponse must run the very plan PreRequest ran")
			assert.Empty(t, pre.Policies, "the plan runs alone; no consumer-wide list to fall back to")
			if tc.static {
				assert.Same(t, f.rc.MCPPlans.PlanFor(reg, tc.tool, nil), pre.Plan,
					"a destination without principal-scoped matches runs its precompiled plan")
			}
			assert.ElementsMatch(t, tc.wantPolicies, f.executed(t, pre.Plan))
		})
	}
}

// A call nobody can serve is answered by Resolve, before any stage runs: no
// plugin sees a tool that does not exist, that the toolkit forbids, or whose
// upstream still awaits consent.
func TestRPCGateway_ToolsCall_ResolveErrorSkipsPlugins(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
	}{
		{name: "unknown tool", err: fmt.Errorf("%w: ghost", appmcp.ErrToolNotFound)},
		{name: "toolkit denied", err: &appmcp.ToolNotPermittedError{Tool: "ghost"}},
		{name: "consent pending", err: &appmcp.ConsentRequiredError{Provider: "com.notion/mcp", Ticket: "tk", Path: "/p/mcp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			composer := mocks.NewComposer(t)
			composer.EXPECT().Resolve(mock.Anything, mock.Anything, "ghost").Return(nil, tc.err).Once()
			exec := pluginmocks.NewExecutor(t)

			g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
			res, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "tools/call",
				json.RawMessage(`{"name":"ghost","arguments":{}}`))

			assert.Nil(t, res)
			require.ErrorIs(t, err, tc.err)
			exec.AssertNotCalled(t, "RunStage", mock.Anything, mock.Anything)
			composer.AssertNotCalled(t, "Invoke", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// Plugins see the binding Resolve fixed: the registry and the native tool in
// RegistryID and metadata, while the body keeps the name the caller used. On a
// federated consumer those differ, and a policy scoped to run_query has to
// match whatever hash the caller typed.
func TestRPCGateway_ToolsCall_PluginsSeeTheResolvedBinding(t *testing.T) {
	t.Parallel()
	const exposed = "mcp_ab12_run_query_9f8e"
	reg := stubRegistry("snowflake")
	target := resolvedToolOn(reg, "run_query", exposed)
	composer := mocks.NewComposer(t)
	composer.EXPECT().Resolve(mock.Anything, mock.Anything, exposed).Return(target, nil).Once()
	composer.EXPECT().Invoke(mock.Anything, mock.Anything, target, mock.Anything).
		Return(json.RawMessage(`{"content":[]}`), nil).Once()

	exec := pluginmocks.NewExecutor(t)
	var seen []*infracontext.RequestContext
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) { seen = append(seen, in.Request) }).
		Return(&appplugins.StageOutcome{}, nil).Twice()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	_, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "tools/call",
		json.RawMessage(`{"name":"`+exposed+`","arguments":{"sql":"select 1"}}`))
	require.NoError(t, err)

	require.Len(t, seen, 2)
	for _, req := range seen {
		require.NotNil(t, req)
		assert.True(t, req.MCP)
		assert.Equal(t, reg.ID.String(), req.RegistryID)
		assert.Equal(t, "run_query", req.Metadata[infracontext.MetadataMCPTool])
		assert.Equal(t, reg.ID.String(), req.Metadata[infracontext.MetadataMCPRegistryID])
		assert.Equal(t, "snowflake", req.Metadata[infracontext.MetadataMCPRegistryName])
		assert.Equal(t, exposed, req.Metadata[infracontext.MetadataMCPExposedTool])
		var body struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		require.NoError(t, json.Unmarshal(req.Body, &body))
		assert.Equal(t, exposed, body.Name, "Body.name stays the name the caller used")
		assert.JSONEq(t, `{"sql":"select 1"}`, string(body.Arguments))
	}
}

// A body writer may rewrite the arguments, and the upstream receives the
// rewrite. It may also rewrite the name, and that changes nothing: the call
// still goes to the target Resolve bound before the plugin ran.
func TestRPCGateway_ToolsCall_RewrittenNameDoesNotReroute(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	target := expectResolve(composer, "echo")
	var invoked *appmcp.ResolvedTool
	var forwarded json.RawMessage
	composer.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ *appconsumer.RoutableConsumer, got *appmcp.ResolvedTool, args json.RawMessage) {
			invoked, forwarded = got, args
		}).
		Return(json.RawMessage(`{"content":[]}`), nil).Once()

	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) {
			if in.Stage == policydomain.StagePreRequest {
				in.Request.Body = []byte(`{"name":"delete_everything","arguments":{"q":"[REDACTED]"}}`)
			}
		}).
		Return(&appplugins.StageOutcome{}, nil).Twice()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	_, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "tools/call",
		json.RawMessage(`{"name":"echo","arguments":{"q":"secret"}}`))
	require.NoError(t, err)

	assert.Same(t, target, invoked, "the upstream call must use the resolved target, not the rewritten name")
	assert.JSONEq(t, `{"q":"[REDACTED]"}`, string(forwarded), "the rewritten arguments do travel")
}

// A consumer without precompiled MCP plans is the pre-scope world: the runner
// gets no plan from the dispatcher and falls back to the consumer-wide
// PolicyPlan and Policies, exactly as before.
func TestRPCGateway_ToolsCall_WithoutMCPPlansRunsTheConsumerPlan(t *testing.T) {
	t.Parallel()
	rc := mcpRoutableConsumer()
	rc.Policies = []*policydomain.Policy{{
		Enabled: true,
		Stages:  []policydomain.Stage{policydomain.StagePreRequest, policydomain.StagePreResponse},
	}}
	rc.PolicyPlan = &appplugins.StagePlan{}
	require.Nil(t, rc.MCPPlans)

	composer := mocks.NewComposer(t)
	expectToolCall(composer, "echo", json.RawMessage(`{"content":[]}`), nil)
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.MatchedBy(func(in appplugins.StageInput) bool {
		return in.Plan == rc.PolicyPlan && len(in.Policies) == len(rc.Policies)
	})).Return(&appplugins.StageOutcome{}, nil).Twice()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	_, err := g.Dispatch(context.Background(), rc, "tools/call", json.RawMessage(`{"name":"echo"}`))
	require.NoError(t, err)
}

// RUN-832: an executor failure that is not a policy decision (guard down,
// decode error) never denies the call. The upstream is still invoked and its
// result still returned, in both directions.
func TestRPCGateway_ToolsCall_NonBlockExecutorErrorFailsOpen(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	composer := mocks.NewComposer(t)
	expectToolCall(composer, "echo", raw, nil)
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, errors.New("guard down")).Twice()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	res, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "tools/call", json.RawMessage(`{"name":"echo"}`))

	require.NoError(t, err)
	got, ok := res.(json.RawMessage)
	require.True(t, ok, "result = %#v, want json.RawMessage", res)
	assert.Equal(t, string(raw), string(got))
}
