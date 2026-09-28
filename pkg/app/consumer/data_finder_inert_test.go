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
	"bytes"
	"context"
	"log/slog"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	backendmocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// No production plugin opts into inert planes yet — which ones may is an open
// product decision (RUN-1621, open question 2) — so the cross-plane behaviour
// is only observable through a plugin declared here. nameGatingSlug is the
// other half of the pair: a plugin that never opted in, which is what every
// production plugin looks like today.
const (
	inertSafeSlug  = "inert_safe_guard"
	inertSafeSlugB = "inert_safe_guard_b"
	nameGatingSlug = "name_gating_guard"
)

type inertSafePlugin struct {
	recordingPlugin
}

func (p *inertSafePlugin) ScopeInertSafe() bool { return true }

type inertHarness struct {
	t   *testing.T
	reg appplugins.Registry
	rec *planRecorder
}

func newInertHarness(t *testing.T) *inertHarness {
	t.Helper()
	rec := &planRecorder{}
	reg := appplugins.NewRegistry()
	for _, slug := range []string{inertSafeSlug, inertSafeSlugB} {
		require.NoError(t, reg.Register(&inertSafePlugin{recordingPlugin{name: slug, rec: rec}}))
	}
	require.NoError(t, reg.Register(&recordingPlugin{name: nameGatingSlug, rec: rec}))
	return &inertHarness{t: t, reg: reg, rec: rec}
}

func (h *inertHarness) executedPlan(plan *appplugins.StagePlan) []string {
	h.t.Helper()
	return h.run(appplugins.StageInput{Stage: policydomain.StagePreRequest, Plan: plan})
}

// executedFallback drives the path the executor takes when PolicyPlan is nil:
// it rebuilds the chain from Policies with buildStageChain and does not flatten
// the specificity. Comparing it with executedPlan is what makes a regression on
// the nil-plan guarantee visible.
func (h *inertHarness) executedFallback(policies []*policydomain.Policy) []string {
	h.t.Helper()
	return h.run(appplugins.StageInput{Stage: policydomain.StagePreRequest, Policies: policies})
}

func (h *inertHarness) run(in appplugins.StageInput) []string {
	h.rec.drain()
	in.Request = &infracontext.RequestContext{}
	in.Response = &infracontext.ResponseContext{}
	_, err := appplugins.NewExecutor(h.reg, nil).RunStage(context.Background(), in)
	require.NoError(h.t, err)
	return h.rec.drain()
}

func inertPolicy(
	gwID ids.GatewayID,
	name, slug string,
	scope *policydomain.MCPScope,
	consumerIDs ...ids.ConsumerID,
) *policydomain.Policy {
	return &policydomain.Policy{
		ID:          ids.New[ids.PolicyKind](),
		GatewayID:   gwID,
		Name:        name,
		Slug:        slug,
		Enabled:     true,
		ConsumerIDs: consumerIDs,
		Stages:      []policydomain.Stage{policydomain.StagePreRequest},
		MCPScope:    scope,
	}
}

func groupScope(groups ...string) *policydomain.MCPScope {
	return &policydomain.MCPScope{Groups: groups}
}

func loadInert(
	t *testing.T,
	gwID ids.GatewayID,
	reg appplugins.Registry,
	logger *slog.Logger,
	consumers []*domain.Consumer,
	policies []*policydomain.Policy,
) *appconsumer.Data {
	t.Helper()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(consumers, nil).Once()
	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(policies, nil).Once()
	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).Return(nil, nil).Maybe()
	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).Return(nil, nil).Maybe()

	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authRepo, reg, newCacheManager(), logger)
	data, err := finder.FindByGateway(context.Background(), gwID)
	require.NoError(t, err)
	return data
}

func consumerByID(t *testing.T, data *appconsumer.Data, id ids.ConsumerID) appconsumer.RoutableConsumer {
	t.Helper()
	for _, rc := range data.Consumers {
		if rc.Consumer != nil && rc.Consumer.ID == id {
			return rc
		}
	}
	t.Fatalf("consumer %s missing from the aggregate", id)
	return appconsumer.RoutableConsumer{}
}

func policySlugs(policies []*policydomain.Policy) []string {
	out := make([]string, 0, len(policies))
	for _, p := range policies {
		out = append(out, p.Slug)
	}
	return out
}

// The central statement of RUN-1621 (§2.1, §2.2): the consumer dimension gates
// in both planes and the group dimension is inert outside MCP. A group-only
// policy attached to X therefore runs in X's LLM chain and in nobody else's.
func TestDataFinder_FindByGateway_GroupOnlyScopeRunsOnItsOwnConsumerOnly(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	x := routableConsumer(gwID, nil)
	y := routableConsumer(gwID, nil)
	h := newInertHarness(t)

	byGroup := inertPolicy(gwID, "G", inertSafeSlug, groupScope("finance"), x.ID)
	byRegistry := inertPolicy(gwID, "R", inertSafeSlug,
		&policydomain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}}, x.ID)
	unrouted := inertPolicy(gwID, "U", inertSafeSlug, groupScope("finance"))

	data := loadInert(t, gwID, h.reg, newTestLogger(),
		[]*domain.Consumer{x, y}, []*policydomain.Policy{byGroup, byRegistry, unrouted})

	rcX := consumerByID(t, data, x.ID)
	rcY := consumerByID(t, data, y.ID)

	assert.Equal(t, []string{"G"}, h.executedPlan(rcX.PolicyPlan),
		"a group-only policy attached to X runs in X's LLM chain")
	assert.Empty(t, h.executedPlan(rcY.PolicyPlan),
		"and never leaks into another consumer's chain")
	assert.False(t, containsPolicyID(rcX.Policies, byRegistry.ID),
		"a registry scope reaches no non-MCP plane")

	// The policy with no consumers and no global is absent because loadPolicies
	// routes it neither to globals nor to byConsumer. Nothing in the inert path
	// filters it out, and nothing should: if this assertion ever needs a new
	// filter to hold, the routing changed underneath it.
	for _, rc := range []appconsumer.RoutableConsumer{rcX, rcY} {
		assert.False(t, containsPolicyID(rc.Policies, unrouted.ID))
		assert.False(t, containsPolicyID(rc.ScopedPolicies, unrouted.ID),
			"a policy with no consumers and no global never reaches a consumer at all")
	}
}

// The executor reads Policies and Plan and rebuilds the chain from Policies
// whenever Plan is nil — through buildStageChain(..., false), which does not
// flatten the specificity. Phase 2 answers that by never leaving a non-MCP
// PolicyPlan nil, so that path is unreachable for the only consumers whose
// Policies can hold a scoped policy. This test fails if that guarantee is
// undone.
func TestDataFinder_FindByGateway_NonMCPPlanIsNeverNil(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	cons := routableConsumer(gwID, nil)
	h := newInertHarness(t)

	// The scoped policy's slug sorts after the unscoped one, so an unflattened
	// specificity of 1 pulls it ahead and the two chains diverge.
	unscoped := inertPolicy(gwID, "U", inertSafeSlug, nil, cons.ID)
	byGroup := inertPolicy(gwID, "G", inertSafeSlugB, groupScope("finance"), cons.ID)

	data := loadInert(t, gwID, h.reg, newTestLogger(),
		[]*domain.Consumer{cons}, []*policydomain.Policy{unscoped, byGroup})
	rc := consumerByID(t, data, cons.ID)

	require.NotNil(t, rc.PolicyPlan,
		"a non-MCP consumer must always carry a plan: the nil-plan fallback orders with specificity 1")
	assert.ElementsMatch(t, []string{inertSafeSlug, inertSafeSlugB}, policySlugs(rc.Policies))
	assert.Equal(t, []string{"U", "G"}, h.executedPlan(rc.PolicyPlan),
		"the inert plan leaves the order at priority, slug, id")

	// The reason the guarantee is not optional. If the fallback is ever taught
	// to flatten as well, this is the assertion to revisit.
	assert.NotEqual(t, h.executedPlan(rc.PolicyPlan), h.executedFallback(rc.Policies),
		"the nil-plan fallback would run a different chain, which is why PolicyPlan must never be nil here")
}

func TestDataFinder_FindByGateway_NonMCPPlanSurvivesAnEmptyGateway(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		withReg  bool
		policies []*policydomain.Policy
	}{
		{name: "no policies at all", withReg: true},
		{name: "no plugin registry", withReg: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			cons := routableConsumer(gwID, nil)
			var reg appplugins.Registry
			if tc.withReg {
				reg = newInertHarness(t).reg
			}
			data := loadInert(t, gwID, reg, newTestLogger(), []*domain.Consumer{cons}, tc.policies)
			assert.NotNil(t, consumerByID(t, data, cons.ID).PolicyPlan,
				"the guarantee has no exceptions: every branch that builds a non-MCP consumer builds its plan")
		})
	}
}

// The invariant of §3: editing a policy's mcp_scope adds or removes that one
// entry and never reorders the rest.
func TestDataFinder_FindByGateway_InertPlanKeepsTheOrderOfTheUnscopedChain(t *testing.T) {
	t.Parallel()
	h := newInertHarness(t)

	order := func(scope *policydomain.MCPScope) []string {
		gwID := ids.New[ids.GatewayKind]()
		cons := routableConsumer(gwID, nil)
		first := inertPolicy(gwID, "A", inertSafeSlug, nil, cons.ID)
		second := inertPolicy(gwID, "B", nameGatingSlug, nil, cons.ID)
		scoped := inertPolicy(gwID, "C", inertSafeSlugB, scope, cons.ID)
		data := loadInert(t, gwID, h.reg, newTestLogger(),
			[]*domain.Consumer{cons}, []*policydomain.Policy{first, second, scoped})
		return h.executedPlan(consumerByID(t, data, cons.ID).PolicyPlan)
	}

	withoutScope := order(nil)
	withGroups := order(groupScope("finance"))

	require.Contains(t, withoutScope, "C")
	require.Contains(t, withGroups, "C")
	assert.Equal(t, withoutScope, withGroups,
		"adding a group to a scope must not move the policy, nor anything around it")
}

// RUN-1621, rule 2, in the literal shape of §3.2.1: a deny-all tool allowlist
// narrowed to except_groups would turn into a deny-all for every function call
// of the consumer. The plugin never opted in, so it does not cross — but it
// still gates in MCP, where the group is real.
func TestDataFinder_FindByGateway_NameGatingPluginNeverCrosses(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	llm := routableConsumer(gwID, nil)
	mcpCons := mcpRoutableConsumer(gwID)
	h := newInertHarness(t)

	denyAll := inertPolicy(gwID, "D", nameGatingSlug,
		&policydomain.MCPScope{ExceptGroups: []string{"finance"}}, llm.ID, mcpCons.ID)
	optedIn := inertPolicy(gwID, "I", inertSafeSlug,
		&policydomain.MCPScope{ExceptGroups: []string{"finance"}}, llm.ID)

	data := loadInert(t, gwID, h.reg, newTestLogger(),
		[]*domain.Consumer{llm, mcpCons}, []*policydomain.Policy{denyAll, optedIn})

	rcLLM := consumerByID(t, data, llm.ID)
	assert.False(t, containsPolicyID(rcLLM.Policies, denyAll.ID),
		"a plugin that gates by tool name must not run where the group no longer gates")
	assert.True(t, containsPolicyID(rcLLM.Policies, optedIn.ID),
		"the same scope on a plugin that opted in does cross")

	rcMCP := consumerByID(t, data, mcpCons.ID)
	assert.True(t, containsPolicyID(rcMCP.ScopedPolicies, denyAll.ID),
		"the opt-in is about inert planes only: in MCP the policy still gates")
	assert.False(t, containsPolicyID(rcMCP.Policies, denyAll.ID),
		"and it stays out of the MCP base chain, as every scoped policy does")
}

// RUN-1621, rule 1: the tombstone the #785 migration writes runs in no plane.
func TestDataFinder_FindByGateway_TombstoneRunsInNoPlane(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	llm := routableConsumer(gwID, nil)
	mcpCons := mcpRoutableConsumer(gwID)
	h := newInertHarness(t)

	tombstone := inertPolicy(gwID, "T", inertSafeSlug, &policydomain.MCPScope{}, llm.ID, mcpCons.ID)

	data := loadInert(t, gwID, h.reg, newTestLogger(),
		[]*domain.Consumer{llm, mcpCons}, []*policydomain.Policy{tombstone})

	rcLLM := consumerByID(t, data, llm.ID)
	assert.Empty(t, h.executedPlan(rcLLM.PolicyPlan), "a tombstone must not wake up on an inert plane")
	assert.False(t, containsPolicyID(rcLLM.Policies, tombstone.ID))

	rcMCP := consumerByID(t, data, mcpCons.ID)
	assert.Empty(t, h.executedPlan(rcMCP.PolicyPlan))
	require.NotNil(t, rcMCP.MCPPlans)
	assert.Empty(t, h.executedPlan(rcMCP.MCPPlans.PlanFor(nil, "run_query", nil)),
		"nor in the MCP plane, where it already meant matches-nothing")
}

// RUN-1621, rule 3.6: inertness collapses levels the write-side level guard
// accepted as distinct, so the load path resolves the collision. Three cases,
// in order.
func TestDataFinder_FindByGateway_CoalescesCrossingPoliciesOfTheSameSlug(t *testing.T) {
	t.Parallel()

	t.Run("an unscoped policy of the same slug wins", func(t *testing.T) {
		t.Parallel()
		gwID := ids.New[ids.GatewayKind]()
		cons := routableConsumer(gwID, nil)
		h := newInertHarness(t)
		var logs bytes.Buffer

		unscoped := inertPolicy(gwID, "U", inertSafeSlug, nil, cons.ID)
		byGroup := inertPolicy(gwID, "G", inertSafeSlug, groupScope("finance"), cons.ID)

		data := loadInert(t, gwID, h.reg, warnLogger(&logs),
			[]*domain.Consumer{cons}, []*policydomain.Policy{unscoped, byGroup})
		rc := consumerByID(t, data, cons.ID)

		assert.Equal(t, []string{"U"}, h.executedPlan(rc.PolicyPlan))
		assert.Contains(t, logs.String(), "collapse onto an unscoped policy")
	})

	t.Run("exactly one collapsed policy runs", func(t *testing.T) {
		t.Parallel()
		gwID := ids.New[ids.GatewayKind]()
		cons := routableConsumer(gwID, nil)
		h := newInertHarness(t)

		byGroup := inertPolicy(gwID, "G", inertSafeSlug, groupScope("finance"), cons.ID)

		data := loadInert(t, gwID, h.reg, newTestLogger(),
			[]*domain.Consumer{cons}, []*policydomain.Policy{byGroup})

		assert.Equal(t, []string{"G"}, h.executedPlan(consumerByID(t, data, cons.ID).PolicyPlan),
			"the product requirement: a group-scoped policy still applies on the LLM plane")
	})

	// consumer X + groups[finance] and consumer X + groups[engineering] are two
	// distinct levels in MCP and legitimate configuration there. On X's LLM
	// plane both fall to (X, all, all), and running either one of two
	// contradictory configurations is worse than running neither.
	t.Run("two or more collapsed policies leave none running", func(t *testing.T) {
		t.Parallel()
		gwID := ids.New[ids.GatewayKind]()
		cons := routableConsumer(gwID, nil)
		h := newInertHarness(t)
		var logs bytes.Buffer

		finance := inertPolicy(gwID, "F", inertSafeSlug, groupScope("finance"), cons.ID)
		engineering := inertPolicy(gwID, "E", inertSafeSlug, groupScope("engineering"), cons.ID)
		other := inertPolicy(gwID, "O", inertSafeSlugB, groupScope("finance"), cons.ID)

		data := loadInert(t, gwID, h.reg, warnLogger(&logs),
			[]*domain.Consumer{cons}, []*policydomain.Policy{finance, engineering, other})
		rc := consumerByID(t, data, cons.ID)

		assert.Equal(t, []string{"O"}, h.executedPlan(rc.PolicyPlan),
			"the collision is per slug: another slug of the same consumer still runs")
		out := logs.String()
		assert.Contains(t, out, "none of them runs")
		assert.Contains(t, out, "F")
		assert.Contains(t, out, "E")
	})

	// A disabled policy runs nowhere, so it holds no level: it must not knock
	// out the enabled policy it collides with, by either of the two routes.
	t.Run("a disabled policy occupies no level", func(t *testing.T) {
		t.Parallel()
		gwID := ids.New[ids.GatewayKind]()
		cons := routableConsumer(gwID, nil)
		h := newInertHarness(t)

		enabled := inertPolicy(gwID, "G", inertSafeSlug, groupScope("finance"), cons.ID)
		disabledPeer := inertPolicy(gwID, "D", inertSafeSlug, groupScope("engineering"), cons.ID)
		disabledPeer.Enabled = false
		disabledUnscoped := inertPolicy(gwID, "U", inertSafeSlug, nil, cons.ID)
		disabledUnscoped.Enabled = false

		data := loadInert(t, gwID, h.reg, newTestLogger(), []*domain.Consumer{cons},
			[]*policydomain.Policy{enabled, disabledPeer, disabledUnscoped})

		assert.Equal(t, []string{"G"}, h.executedPlan(consumerByID(t, data, cons.ID).PolicyPlan))
	})
}

func warnLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}
