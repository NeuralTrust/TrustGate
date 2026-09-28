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
	"encoding/json"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	benchNoScope        = "no_scope"
	benchStaticScope    = "static_scope"
	benchPrincipalScope = "principal_scoped"
)

// benchComposer answers Resolve and Invoke from memory, the shape of a
// composer whose discovery cache is warm. The remaining methods are never
// reached from tools/call.
type benchComposer struct {
	target *ResolvedTool
	result json.RawMessage
}

var _ Composer = (*benchComposer)(nil)

func (c *benchComposer) Resolve(context.Context, *appconsumer.RoutableConsumer, string) (*ResolvedTool, error) {
	return c.target, nil
}

func (c *benchComposer) Invoke(context.Context, *appconsumer.RoutableConsumer, *ResolvedTool, json.RawMessage) (json.RawMessage, error) {
	return c.result, nil
}

func (c *benchComposer) ListTools(context.Context, *appconsumer.RoutableConsumer) ([]Tool, error) {
	return nil, nil
}

func (c *benchComposer) ListResources(context.Context, *appconsumer.RoutableConsumer) ([]Resource, error) {
	return nil, nil
}

func (c *benchComposer) ListResourceTemplates(context.Context, *appconsumer.RoutableConsumer) ([]ResourceTemplate, error) {
	return nil, nil
}

func (c *benchComposer) ReadResource(context.Context, *appconsumer.RoutableConsumer, string) (json.RawMessage, error) {
	return nil, nil
}

func (c *benchComposer) ListPrompts(context.Context, *appconsumer.RoutableConsumer) ([]Prompt, error) {
	return nil, nil
}

func (c *benchComposer) GetPrompt(context.Context, *appconsumer.RoutableConsumer, string, map[string]string) (json.RawMessage, error) {
	return nil, nil
}

func (c *benchComposer) ToolInventory(context.Context, *appconsumer.RoutableConsumer) (*ToolInventory, error) {
	return nil, nil
}

// passExecutor lets every stage through, so the measurement is the dispatcher,
// the plan selection and the runner's request context rather than plugin work.
type passExecutor struct{}

func (passExecutor) RunStage(context.Context, appplugins.StageInput) (*appplugins.StageOutcome, error) {
	return &appplugins.StageOutcome{}, nil
}

type benchPlugin struct{ name string }

func (p *benchPlugin) Name() string                          { return p.name }
func (p *benchPlugin) MandatoryStages() []policydomain.Stage { return nil }
func (p *benchPlugin) SupportedStages() []policydomain.Stage {
	return []policydomain.Stage{policydomain.StagePreRequest, policydomain.StagePreResponse}
}
func (p *benchPlugin) SupportedModes() []policydomain.Mode {
	return []policydomain.Mode{policydomain.ModeEnforce}
}
func (p *benchPlugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolMCP}
}
func (p *benchPlugin) ValidateConfig(map[string]any) error { return nil }
func (p *benchPlugin) MutatesRequestBody() bool            { return false }
func (p *benchPlugin) MutatesResponseBody() bool           { return false }
func (p *benchPlugin) MutatesMetadata() bool               { return false }
func (p *benchPlugin) Execute(context.Context, appplugins.ExecInput) (*appplugins.Result, error) {
	return &appplugins.Result{StatusCode: 200}, nil
}

func benchPolicy(name, slug string, scope *policydomain.MCPScope) *policydomain.Policy {
	return &policydomain.Policy{
		ID:       ids.New[ids.PolicyKind](),
		Name:     name,
		Slug:     slug,
		Enabled:  true,
		Stages:   []policydomain.Stage{policydomain.StagePreRequest, policydomain.StagePreResponse},
		MCPScope: scope,
	}
}

func benchRegistry(name string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Name:      name,
		Enabled:   true,
		MCPTarget: &registrydomain.MCPTarget{URL: "https://" + name + ".example.com/mcp"},
	}
}

// benchFixture is a consumer bound to registries x and y whose tools/call
// lands on run_query of x. no_scope carries no precompiled plans; static_scope
// adds a policy on (x, run_query) and one on y, both without principal;
// principal_scoped adds a group-scoped policy on x that the caller matches, so
// PlanFor pays the principal filter and the plan union on every call.
//
// Every variant but no_scope carries an authenticated principal, because a
// real MCP caller has one. static_scope is the case that matters: a principal
// is present but no scoped policy can read it, so nothing must project it.
type benchFixture struct {
	rc        *appconsumer.RoutableConsumer
	target    *ResolvedTool
	principal *identity.Principal
}

func newBenchFixture(tb testing.TB, variant string) benchFixture {
	tb.Helper()
	reg := appplugins.NewRegistry()
	for _, slug := range []string{"plugin-a", "plugin-b", "plugin-c", "plugin-d"} {
		require.NoError(tb, reg.Register(&benchPlugin{name: slug}))
	}
	x, y := benchRegistry("x"), benchRegistry("y")
	unscoped := []*policydomain.Policy{benchPolicy("C", "plugin-c", nil)}
	scoped := []*policydomain.Policy{
		benchPolicy("A", "plugin-a", &policydomain.MCPScope{
			Tools: []policydomain.MCPToolRef{{RegistryID: x.ID, Tool: "run_query"}},
		}),
		benchPolicy("B", "plugin-b", &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{y.ID}}),
	}
	if variant == benchPrincipalScope {
		scoped = append(scoped, benchPolicy("D", "plugin-d", &policydomain.MCPScope{
			RegistryIDs: []ids.RegistryID{x.ID},
			Groups:      []string{"Finanzas"},
		}))
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:        ids.New[ids.ConsumerKind](),
			GatewayID: ids.New[ids.GatewayKind](),
			Type:      consumerdomain.TypeMCP,
		},
		Policies:   unscoped,
		PolicyPlan: appplugins.NewStagePlan(reg, unscoped, discardLogger()),
	}
	if variant != benchNoScope {
		rc.ScopedPolicies = scoped
		rc.MCPPlans = appconsumer.BuildPolicyPlans(reg, unscoped, scoped, discardLogger())
	}
	f := benchFixture{
		rc:     rc,
		target: &ResolvedTool{Registry: x, Tool: Tool{Name: "run_query"}, Exposed: "run_query"},
	}
	if variant != benchNoScope {
		f.principal = &identity.Principal{
			Subject: "usr_finance",
			Method:  identity.MethodExternalJWT,
			Claims:  map[string]any{"groups": []string{"Finanzas"}},
		}
	}
	return f
}

func (f benchFixture) ctx() context.Context {
	if f.principal == nil {
		return context.Background()
	}
	return identity.WithPrincipal(context.Background(), f.principal)
}

// tracedCtx is f.ctx() with the RequestTrace and MCP span the HTTP layer
// installs on every request that carries telemetry. It is the path production
// takes: with a span present the dispatcher goes through Explain, which walks
// every scoped policy of the consumer, and not through PlanFor. Benchmarking
// only the untraced context would report the cheap half.
func (f benchFixture) tracedCtx() context.Context {
	ctx := f.ctx()
	rt := trace.New("bench-trace", trace.Metadata{})
	span := rt.StartSpan(trace.SpanMCP, "tools/call")
	return trace.NewSpanContext(trace.NewContext(ctx, rt), span)
}

func BenchmarkRPCDispatcher_CallTool(b *testing.B) {
	params := json.RawMessage(`{"name":"run_query","arguments":{"q":"select 1"}}`)
	result := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	for _, variant := range []string{benchNoScope, benchStaticScope, benchPrincipalScope} {
		for _, traced := range []bool{false, true} {
			name := variant + "/untraced"
			if traced {
				name = variant + "/traced"
			}
			b.Run(name, func(b *testing.B) {
				f := newBenchFixture(b, variant)
				d := NewRPCDispatcher(
					&benchComposer{target: f.target, result: result},
					NewPluginRunner(passExecutor{}, discardLogger()),
					nil, nil, nil,
				)
				ctx := f.ctx()
				if traced {
					ctx = f.tracedCtx()
				}
				b.ReportAllocs()
				for b.Loop() {
					if _, err := d.Dispatch(ctx, f.rc, "", "tools/call", params); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// Plan selection without principal-scoped policies for the destination is two
// map lookups; a consumer with no plans at all falls back before even that.
// AllocsPerRun refuses to run inside a parallel test, so this one is serial.
func TestPlanFor_WithoutPrincipalScopeAllocatesNothing(t *testing.T) {
	for _, variant := range []string{benchNoScope, benchStaticScope} {
		t.Run(variant, func(t *testing.T) {
			f := newBenchFixture(t, variant)
			ctx := f.ctx()
			allocs := testing.AllocsPerRun(1000, func() { planFor(ctx, f.rc, f.target) })
			assert.Zero(t, allocs, "planFor must not allocate on the %s path", variant)
		})
	}
}

// With a span in the context the dispatcher builds a scope decision, which is
// where the allocations of a traced tools/call live. A consumer scoped purely
// by destination must not pay for the caller projection on top: no scoped
// policy of it can read the principal.
func TestPlanFor_TracedStaticScopeDoesNotProjectTheCaller(t *testing.T) {
	f := newBenchFixture(t, benchStaticScope)
	ctx := f.tracedCtx()
	allocs := testing.AllocsPerRun(1000, func() { planFor(ctx, f.rc, f.target) })
	// The six are the decision's matched and skipped lists, the two the span's
	// shape needs and the two the span copies for itself. The caller is not
	// among them: no scoped policy of this consumer narrows by principal, so
	// the group list is never rebuilt out of the token claims.
	assert.LessOrEqual(t, allocs, float64(6),
		"a traced static-scope call should only allocate the scope decision, got %v allocs", allocs)
}

func TestPlanFor_PrincipalScopeUnionsMatchingPolicy(t *testing.T) {
	t.Parallel()
	f := newBenchFixture(t, benchPrincipalScope)
	static := planFor(context.Background(), f.rc, f.target)
	matched := planFor(f.ctx(), f.rc, f.target)
	require.NotNil(t, static)
	require.NotNil(t, matched)
	assert.NotSame(t, static, matched, "a matching principal must union its policy into the static plan")
	assert.True(t, matched.Has(policydomain.StagePreRequest))
}
