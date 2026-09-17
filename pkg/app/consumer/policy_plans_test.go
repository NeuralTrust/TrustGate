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

package consumer_test

import (
	"context"
	"sync"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type planRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *planRecorder) record(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, name)
}

func (r *planRecorder) drain() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.seen...)
	r.seen = nil
	return out
}

type recordingPlugin struct {
	name string
	rec  *planRecorder
}

func (p *recordingPlugin) Name() string                          { return p.name }
func (p *recordingPlugin) MandatoryStages() []policydomain.Stage { return nil }
func (p *recordingPlugin) SupportedStages() []policydomain.Stage {
	return []policydomain.Stage{policydomain.StagePreRequest}
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

type planHarness struct {
	t   *testing.T
	reg appplugins.Registry
	rec *planRecorder
}

func newPlanHarness(t *testing.T, slugs ...string) *planHarness {
	t.Helper()
	rec := &planRecorder{}
	reg := appplugins.NewRegistry()
	for _, slug := range slugs {
		require.NoError(t, reg.Register(&recordingPlugin{name: slug, rec: rec}))
	}
	return &planHarness{t: t, reg: reg, rec: rec}
}

func (h *planHarness) build(unscoped, scoped []*policydomain.Policy) *appconsumer.PolicyPlans {
	return appconsumer.BuildPolicyPlans(h.reg, unscoped, scoped, newTestLogger())
}

func (h *planHarness) executed(plan *appplugins.StagePlan) []string {
	h.t.Helper()
	h.rec.drain()
	_, err := appplugins.NewExecutor(h.reg, nil).RunStage(context.Background(), appplugins.StageInput{
		Stage:    policydomain.StagePreRequest,
		Plan:     plan,
		Request:  &infracontext.RequestContext{},
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(h.t, err)
	return h.rec.drain()
}

func preRequestPolicy(name, slug string, scope *policydomain.MCPScope) *policydomain.Policy {
	return &policydomain.Policy{
		ID:       ids.New[ids.PolicyKind](),
		Name:     name,
		Slug:     slug,
		Enabled:  true,
		Stages:   []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope: scope,
	}
}

func registryScope(regs ...ids.RegistryID) *policydomain.MCPScope {
	return &policydomain.MCPScope{RegistryIDs: regs}
}

func toolScope(reg ids.RegistryID, tool string) *policydomain.MCPScope {
	return &policydomain.MCPScope{Tools: []policydomain.MCPToolRef{{RegistryID: reg, Tool: tool}}}
}

func mcpRegistry(id ids.RegistryID) *registrydomain.Registry {
	return &registrydomain.Registry{ID: id, Enabled: true, MCPTarget: &registrydomain.MCPTarget{}}
}

func financePrincipal() *identity.Principal {
	return &identity.Principal{
		Subject: "usr_123",
		Method:  identity.MethodExternalJWT,
		Claims:  map[string]any{"email": "Ana@Acme.com", "groups": []string{"Finanzas"}},
	}
}

func groupPrincipal(group string) *identity.Principal {
	return &identity.Principal{
		Subject: "usr_" + group,
		Method:  identity.MethodExternalJWT,
		Claims:  map[string]any{"groups": []string{group}},
	}
}

func TestPolicyPlans_NilReceiverReturnsNil(t *testing.T) {
	t.Parallel()
	var plans *appconsumer.PolicyPlans
	assert.Nil(t, plans.PlanFor(mcpRegistry(ids.New[ids.RegistryKind]()), "run_query", financePrincipal()))
	assert.Nil(t, appconsumer.BuildPolicyPlans(nil, nil, nil, newTestLogger()),
		"without a plugin registry there is no plan to precompile; the executor keeps its ad-hoc chain")
}

func TestPolicyPlans_WithoutScopedReturnsTheBasePlan(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "c_audit")
	unscoped := preRequestPolicy("C", "c_audit", nil)
	plans := h.build([]*policydomain.Policy{unscoped}, nil)

	x, y := mcpRegistry(ids.New[ids.RegistryKind]()), mcpRegistry(ids.New[ids.RegistryKind]())
	base := plans.PlanFor(x, "run_query", nil)
	require.NotNil(t, base)
	assert.Same(t, base, plans.PlanFor(y, "other", financePrincipal()),
		"with no scoped policies every destination and caller resolves to the same base plan")
	assert.Equal(t, []string{"C"}, h.executed(base))
}

func TestPolicyPlans_ToolBeatsRegistryBeatsBase(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "a_tool", "b_registry", "c_audit", "d_pruned", "e_disabled")
	xID, yID, zID := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	x, y, z := mcpRegistry(xID), mcpRegistry(yID), mcpRegistry(zID)

	a := preRequestPolicy("A", "a_tool", toolScope(xID, "run_query"))
	b := preRequestPolicy("B", "b_registry", registryScope(yID))
	c := preRequestPolicy("C", "c_audit", nil)
	pruned := preRequestPolicy("D", "d_pruned", &policydomain.MCPScope{})
	disabled := preRequestPolicy("E", "e_disabled", registryScope(xID))
	disabled.Enabled = false

	plans := h.build([]*policydomain.Policy{c}, []*policydomain.Policy{a, b, pruned, disabled})

	assert.Equal(t, []string{"A", "C"}, h.executed(plans.PlanFor(x, "run_query", nil)),
		"the (registry, tool) plan carries the tool-scoped policy on top of the base")
	assert.Equal(t, []string{"C"}, h.executed(plans.PlanFor(x, "other", nil)),
		"another tool of the same registry only sees the base")
	assert.Equal(t, []string{"B", "C"}, h.executed(plans.PlanFor(y, "run_query", nil)),
		"a tool scope never leaks to another registry; the registry plan applies")
	assert.Equal(t, []string{"B", "C"}, h.executed(plans.PlanFor(y, "anything", nil)))
	assert.Equal(t, []string{"C"}, h.executed(plans.PlanFor(z, "run_query", nil)))

	assert.Same(t, plans.PlanFor(x, "other", nil), plans.PlanFor(z, "run_query", nil),
		"destinations without static scoped policies share the base plan pointer")
	assert.Same(t, plans.PlanFor(y, "run_query", nil), plans.PlanFor(y, "anything", nil),
		"tools without their own plan share the registry plan pointer")
}

func TestPolicyPlans_InstanceOfResolvesToTheShelfKey(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "shelf_guard", "c_audit")
	shelfID, installID := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()

	plans := h.build(
		[]*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)},
		[]*policydomain.Policy{preRequestPolicy("S", "shelf_guard", registryScope(shelfID))},
	)

	clone := mcpRegistry(installID)
	clone.InstanceOf = shelfID
	assert.Equal(t, []string{"S", "C"}, h.executed(plans.PlanFor(clone, "run_query", nil)),
		"a Store instance clone matches a scope naming its shelf")
	assert.Equal(t, []string{"C"}, h.executed(plans.PlanFor(mcpRegistry(installID), "run_query", nil)),
		"a registry without InstanceOf only matches by its own id")
	assert.Equal(t, []string{"S", "C"}, h.executed(plans.PlanFor(mcpRegistry(shelfID), "run_query", nil)))
}

func TestPolicyPlans_PrincipalScopedPoliciesAreFilteredByTheCaller(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "p_guard", "s_guard", "u_guard", "c_audit")
	xID, yID := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	x, y := mcpRegistry(xID), mcpRegistry(yID)

	byGroup := preRequestPolicy("P", "p_guard", &policydomain.MCPScope{
		RegistryIDs: []ids.RegistryID{xID}, Groups: []string{"Finanzas"},
	})
	bySubject := preRequestPolicy("S", "s_guard", &policydomain.MCPScope{
		Tools: []policydomain.MCPToolRef{{RegistryID: xID, Tool: "run_query"}}, Users: []string{"usr_123"},
	})
	byEmail := preRequestPolicy("U", "u_guard", &policydomain.MCPScope{
		Tools: []policydomain.MCPToolRef{{RegistryID: xID, Tool: "run_query"}}, Users: []string{"ana@acme.com"},
	})
	c := preRequestPolicy("C", "c_audit", nil)
	plans := h.build([]*policydomain.Policy{c}, []*policydomain.Policy{byGroup, bySubject, byEmail})

	emailOnly := &identity.Principal{Method: identity.MethodExternalJWT, Claims: map[string]any{"email": "Ana@Acme.com"}}
	subjectOnly := &identity.Principal{Subject: "usr_123", Method: identity.MethodExternalJWT}

	tests := []struct {
		name      string
		reg       *registrydomain.Registry
		tool      string
		principal *identity.Principal
		want      []string
	}{
		{"group on the registry", x, "other", groupPrincipal("Finanzas"), []string{"P", "C"}},
		{"other group is filtered out", x, "other", groupPrincipal("Marketing"), []string{"C"}},
		{"nil principal never matches groups", x, "other", nil, []string{"C"}},
		{"email matches case-insensitively", x, "run_query", emailOnly, []string{"U", "C"}},
		{"subject matches without email", x, "run_query", subjectOnly, []string{"S", "C"}},
		{"everything matches ordered by specificity", x, "run_query", financePrincipal(), []string{"S", "U", "P", "C"}},
		{"no principal-scoped policies for the registry", y, "run_query", financePrincipal(), []string{"C"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, h.executed(plans.PlanFor(tc.reg, tc.tool, tc.principal)))
		})
	}

	assert.Same(t, plans.PlanFor(x, "other", nil), plans.PlanFor(x, "other", groupPrincipal("Marketing")),
		"when no principal-scoped policy matches the precompiled static plan is returned as is")
}

func TestPolicyPlans_ExceptionsExcludeTheCallerAndSpareIdentitylessCallers(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "e_deny", "c_audit")
	xID := ids.New[ids.RegistryKind]()
	x := mcpRegistry(xID)

	everyoneButFinance := preRequestPolicy("E", "e_deny", &policydomain.MCPScope{
		Tools:        []policydomain.MCPToolRef{{RegistryID: xID, Tool: "run_query"}},
		ExceptGroups: []string{"Finanzas"},
		ExceptUsers:  []string{"bob@acme.com"},
	})
	plans := h.build(
		[]*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)},
		[]*policydomain.Policy{everyoneButFinance},
	)

	bob := &identity.Principal{Subject: "usr_bob", Claims: map[string]any{"email": "Bob@Acme.com"}}
	apiKey := &identity.Principal{Method: identity.MethodAPIKey}

	assert.Equal(t, []string{"E", "C"}, h.executed(plans.PlanFor(x, "run_query", groupPrincipal("Marketing"))))
	assert.Equal(t, []string{"C"}, h.executed(plans.PlanFor(x, "run_query", groupPrincipal("Finanzas"))),
		"except_groups removes the excluded group")
	assert.Equal(t, []string{"C"}, h.executed(plans.PlanFor(x, "run_query", bob)),
		"except_users compares the lowercased email")
	assert.Equal(t, []string{"E", "C"}, h.executed(plans.PlanFor(x, "run_query", nil)),
		"an identity-less caller never falls in an exception")
	assert.Equal(t, []string{"E", "C"}, h.executed(plans.PlanFor(x, "run_query", apiKey)))
	assert.Equal(t, []string{"C"}, h.executed(plans.PlanFor(x, "other", groupPrincipal("Marketing"))),
		"the destination still has to match")
}

func TestPolicyPlans_UnionOfStaticAndPrincipalScopedPolicies(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "r_registry", "g_group", "c_audit")
	xID, yID := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	x, y := mcpRegistry(xID), mcpRegistry(yID)

	plans := h.build(
		[]*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)},
		[]*policydomain.Policy{
			preRequestPolicy("R", "r_registry", registryScope(xID)),
			preRequestPolicy("G", "g_group", &policydomain.MCPScope{Groups: []string{"Finanzas"}}),
		},
	)

	assert.Equal(t, []string{"R", "G", "C"}, h.executed(plans.PlanFor(x, "run_query", groupPrincipal("Finanzas"))),
		"both scoped policies enter the plan, ordered by specificity at equal priority")
	assert.Equal(t, []string{"R", "C"}, h.executed(plans.PlanFor(x, "run_query", groupPrincipal("Marketing"))))
	assert.Equal(t, []string{"G", "C"}, h.executed(plans.PlanFor(y, "run_query", groupPrincipal("Finanzas"))),
		"a principal-only scope applies to any destination")
	assert.Equal(t, []string{"C"}, h.executed(plans.PlanFor(y, "run_query", nil)))
}

func TestPolicyPlans_PlanForAllocatesNothingWithoutPrincipalScopedPolicies(t *testing.T) {
	h := newPlanHarness(t, "a_tool", "b_registry", "c_audit")
	xID, yID, zID := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	x, y, z := mcpRegistry(xID), mcpRegistry(yID), mcpRegistry(zID)

	plans := h.build(
		[]*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)},
		[]*policydomain.Policy{
			preRequestPolicy("A", "a_tool", toolScope(xID, "run_query")),
			preRequestPolicy("B", "b_registry", registryScope(yID)),
		},
	)
	principal := financePrincipal()
	var sink *appplugins.StagePlan

	cases := map[string]func(){
		"tool hit":         func() { sink = plans.PlanFor(x, "run_query", principal) },
		"registry hit":     func() { sink = plans.PlanFor(y, "run_query", principal) },
		"fallback to base": func() { sink = plans.PlanFor(z, "run_query", principal) },
	}
	for name, call := range cases {
		allocs := testing.AllocsPerRun(1000, call)
		assert.Zero(t, allocs, "%s: PlanFor must not allocate, nor read Groups()/Email(), when no principal-scoped policy targets the destination", name)
		require.NotNil(t, sink)
	}
}

func refOf(pol *policydomain.Policy) appconsumer.PolicyRef {
	return appconsumer.PolicyRef{ID: pol.ID.String(), Name: pol.Name, Slug: pol.Slug}
}

func TestPolicyPlans_ExplainReturnsThePlanForPlan(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "a_tool", "b_registry", "c_audit", "d_group")
	xID, yID, zID := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	x, y, z := mcpRegistry(xID), mcpRegistry(yID), mcpRegistry(zID)

	plans := h.build(
		[]*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)},
		[]*policydomain.Policy{
			preRequestPolicy("A", "a_tool", toolScope(xID, "run_query")),
			preRequestPolicy("B", "b_registry", registryScope(yID)),
			preRequestPolicy("D", "d_group", &policydomain.MCPScope{
				RegistryIDs: []ids.RegistryID{xID}, Groups: []string{"Finanzas"},
			}),
		},
	)

	static := []struct {
		name      string
		reg       *registrydomain.Registry
		tool      string
		principal *identity.Principal
	}{
		{"tool hit", x, "run_query", nil},
		{"registry hit", y, "search", nil},
		{"base fallback", z, "run_query", financePrincipal()},
		{"principal-scoped without a match", x, "other", groupPrincipal("Marketing")},
	}
	for _, tc := range static {
		plan, _ := plans.Explain(tc.reg, tc.tool, tc.principal)
		assert.Same(t, plans.PlanFor(tc.reg, tc.tool, tc.principal), plan,
			"%s: Explain must hand back the precompiled plan PlanFor returns", tc.name)
	}

	plan, decision := plans.Explain(x, "run_query", financePrincipal())
	assert.Equal(t, []string{"A", "D", "C"}, h.executed(plan),
		"a principal-scoped match unions the same policies PlanFor unions")
	assert.Equal(t, h.executed(plans.PlanFor(x, "run_query", financePrincipal())), h.executed(plan))
	assert.Equal(t, 3, decision.Evaluated)
	assert.Len(t, decision.Matched, 2)
	assert.Len(t, decision.Skipped, 1)
}

func TestPolicyPlans_ExplainListsMatchedAndSkippedWithReasons(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "jira_guard", "finance_guard", "snowflake_guard", "c_audit")
	jiraID, snowflakeID := ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()

	jira := preRequestPolicy("Jira", "jira_guard", registryScope(jiraID))
	finance := preRequestPolicy("Finanzas", "finance_guard", &policydomain.MCPScope{Groups: []string{"Finanzas"}})
	snowflake := preRequestPolicy("Snowflake", "snowflake_guard", toolScope(snowflakeID, "run_query"))
	plans := h.build(
		[]*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)},
		[]*policydomain.Policy{jira, finance, snowflake},
	)

	plan, decision := plans.Explain(mcpRegistry(snowflakeID), "run_query", groupPrincipal("Marketing"))

	assert.Equal(t, []string{"Snowflake", "C"}, h.executed(plan))
	assert.Equal(t, 3, decision.Evaluated, "only scoped policies are evaluated; the unscoped C never counts")
	assert.Equal(t, []appconsumer.PolicyRef{refOf(snowflake)}, decision.Matched)
	assert.ElementsMatch(t, []appconsumer.SkippedPolicy{
		{PolicyRef: refOf(jira), Reason: policydomain.SkipDestination},
		{PolicyRef: refOf(finance), Reason: policydomain.SkipPrincipal},
	}, decision.Skipped)
}

func TestPolicyPlans_ExplainReportsExceptionsAndDormantScopes(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "e_deny", "p_pruned", "c_audit")
	xID := ids.New[ids.RegistryKind]()
	x := mcpRegistry(xID)

	except := preRequestPolicy("E", "e_deny", &policydomain.MCPScope{
		Tools:        []policydomain.MCPToolRef{{RegistryID: xID, Tool: "run_query"}},
		ExceptGroups: []string{"Finanzas"},
	})
	pruned := preRequestPolicy("P", "p_pruned", &policydomain.MCPScope{})
	plans := h.build(
		[]*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)},
		[]*policydomain.Policy{except, pruned},
	)

	plan, decision := plans.Explain(x, "run_query", groupPrincipal("Finanzas"))
	assert.Equal(t, []string{"C"}, h.executed(plan))
	assert.Equal(t, 2, decision.Evaluated)
	assert.Empty(t, decision.Matched)
	assert.ElementsMatch(t, []appconsumer.SkippedPolicy{
		{PolicyRef: refOf(except), Reason: policydomain.SkipExcept},
		{PolicyRef: refOf(pruned), Reason: policydomain.SkipDestination},
	}, decision.Skipped, "an excluded caller reads except; a scope pruned to {} matches no destination")

	plan, decision = plans.Explain(x, "run_query", groupPrincipal("Marketing"))
	assert.Equal(t, []string{"E", "C"}, h.executed(plan))
	assert.Equal(t, []appconsumer.PolicyRef{refOf(except)}, decision.Matched)
	assert.Equal(t, []appconsumer.SkippedPolicy{
		{PolicyRef: refOf(pruned), Reason: policydomain.SkipDestination},
	}, decision.Skipped)
}

func TestPolicyPlans_ExplainWithoutScopedPoliciesIsEmpty(t *testing.T) {
	t.Parallel()
	h := newPlanHarness(t, "c_audit")
	plans := h.build([]*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)}, nil)
	x := mcpRegistry(ids.New[ids.RegistryKind]())

	plan, decision := plans.Explain(x, "run_query", financePrincipal())
	assert.Same(t, plans.PlanFor(x, "run_query", financePrincipal()), plan)
	assert.Equal(t, appconsumer.ScopeDecision{}, decision)

	var none *appconsumer.PolicyPlans
	plan, decision = none.Explain(x, "run_query", nil)
	assert.Nil(t, plan)
	assert.Equal(t, appconsumer.ScopeDecision{}, decision)
}

// Explain pays only for the decision it returns; the plan selection it shares
// with PlanFor stays free. AllocsPerRun refuses a parallel test, so this one
// is serial.
func TestPolicyPlans_ExplainAllocatesOnlyForTheDecision(t *testing.T) {
	h := newPlanHarness(t, "a_tool", "c_audit")
	xID := ids.New[ids.RegistryKind]()
	x := mcpRegistry(xID)
	unscoped := []*policydomain.Policy{preRequestPolicy("C", "c_audit", nil)}
	withScoped := h.build(unscoped, []*policydomain.Policy{preRequestPolicy("A", "a_tool", toolScope(xID, "run_query"))})
	withoutScoped := h.build(unscoped, nil)
	var sink *appplugins.StagePlan
	var decision appconsumer.ScopeDecision

	assert.Zero(t, testing.AllocsPerRun(1000, func() { sink = withScoped.PlanFor(x, "run_query", nil) }),
		"PlanFor stays allocation-free next to Explain")
	assert.Zero(t, testing.AllocsPerRun(1000, func() { sink, decision = withoutScoped.Explain(x, "run_query", nil) }),
		"with nothing scoped there is no decision to build")
	allocs := testing.AllocsPerRun(1000, func() { sink, decision = withScoped.Explain(x, "run_query", nil) })
	assert.Positive(t, allocs, "Explain builds Matched for the span")
	assert.LessOrEqual(t, allocs, 2.0, "Explain allocates the decision lists and nothing else")
	require.NotNil(t, sink)
	assert.Equal(t, 1, decision.Evaluated)
}
