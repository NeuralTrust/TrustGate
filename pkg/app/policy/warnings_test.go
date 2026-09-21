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

package policy_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func policyWith(gwID ids.GatewayID, slug string, scope *domain.MCPScope, consumers ...ids.ConsumerID) *domain.Policy {
	return &domain.Policy{
		ID:          ids.New[ids.PolicyKind](),
		GatewayID:   gwID,
		Slug:        slug,
		Enabled:     true,
		ConsumerIDs: consumers,
		MCPScope:    scope,
	}
}

// scopedPolicy narrows by group alone, which is the scope that crosses into
// the LLM and A2A planes and where the warnings have something to say.
func scopedPolicy(gwID ids.GatewayID, slug string, consumers ...ids.ConsumerID) *domain.Policy {
	return policyWith(gwID, slug, &domain.MCPScope{Groups: []string{"Finanzas"}}, consumers...)
}

func groupScopedPolicy(gwID ids.GatewayID, slug, group string, consumers ...ids.ConsumerID) *domain.Policy {
	return policyWith(gwID, slug, &domain.MCPScope{Groups: []string{group}}, consumers...)
}

func destinationScopedPolicy(gwID ids.GatewayID, slug string, consumers ...ids.ConsumerID) *domain.Policy {
	scope := &domain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}}
	return policyWith(gwID, slug, scope, consumers...)
}

func unscopedPolicy(gwID ids.GatewayID, slug string, consumers ...ids.ConsumerID) *domain.Policy {
	return policyWith(gwID, slug, nil, consumers...)
}

func mcpConsumer(gwID ids.GatewayID, id ids.ConsumerID) *consumerdomain.Consumer {
	return &consumerdomain.Consumer{ID: id, GatewayID: gwID, Type: consumerdomain.TypeMCP}
}

func llmConsumer(gwID ids.GatewayID, id ids.ConsumerID) *consumerdomain.Consumer {
	return &consumerdomain.Consumer{ID: id, GatewayID: gwID, Type: consumerdomain.TypeLLM}
}

func overlapWarning(consumerID ids.ConsumerID, slug string) string {
	return fmt.Sprintf("consumer %s already runs plugin %s without scope", consumerID, slug)
}

func coalescedWarning(consumerID ids.ConsumerID, slug string) string {
	return fmt.Sprintf("consumer %s is not an MCP consumer and already runs plugin %s without scope: "+
		"the scope is inert on that plane, so both collapse onto the same level and only the unscoped policy runs",
		consumerID, slug)
}

func collapsedLevelWarning(consumerID ids.ConsumerID, slug string) string {
	return fmt.Sprintf("consumer %s is not an MCP consumer and already runs plugin %s under another group-scoped policy: "+
		"the two are distinct levels in MCP but the same level here, "+
		"so the configuration is saved and neither of them runs on that plane",
		consumerID, slug)
}

const (
	dormantWarning = "policy has an empty mcp_scope and runs nowhere; " +
		"set mcp_scope to null to run it everywhere"
	scopeBoundWarning = "policy scope names a registry or a tool: " +
		"it runs on MCP traffic only, never on the LLM or A2A plane"
	orphanWarning = "policy has no consumers and is not global: it runs nowhere"
)

// inertSafePlugin is the plugin mock plus the opt-in the registry mock cannot
// express: IsInertSafe asks for it by type assertion, and a plugin that does
// not implement it is denied.
type inertSafePlugin struct {
	*pluginmocks.Plugin
	safe bool
}

func (p inertSafePlugin) ScopeInertSafe() bool { return p.safe }

// inertSafeRegistry resolves every slug to a plugin that has, or has not,
// opted into running where the scope does not gate.
func inertSafeRegistry(t *testing.T, safe bool) appplugins.Registry {
	t.Helper()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().Get(mock.Anything).Return(inertSafePlugin{Plugin: pluginmocks.NewPlugin(t), safe: safe}, true).Maybe()
	return reg
}

// noAPIKeyAuths is a gateway with no api-key credential at all, so the group
// narrowing gates every caller and the api-key warning has nothing to say.
func noAPIKeyAuths(t *testing.T) authdomain.Repository {
	t.Helper()
	auths := authmocks.NewRepository(t)
	auths.EXPECT().ListEnabledByGatewayAndType(mock.Anything, mock.Anything, authdomain.TypeAPIKey).
		Return(nil, nil).Maybe()
	return auths
}

// apiKeyAuths is a gateway whose listed credentials are enabled api keys.
func apiKeyAuths(t *testing.T, gwID ids.GatewayID, authIDs ...ids.AuthID) authdomain.Repository {
	t.Helper()
	out := make([]*authdomain.Auth, 0, len(authIDs))
	for _, id := range authIDs {
		out = append(out, &authdomain.Auth{ID: id, GatewayID: gwID, Type: authdomain.TypeAPIKey, Enabled: true})
	}
	auths := authmocks.NewRepository(t)
	auths.EXPECT().ListEnabledByGatewayAndType(mock.Anything, gwID, authdomain.TypeAPIKey).
		Return(out, nil).Maybe()
	return auths
}

func apiKeyIgnoresGroupsWarning(consumerID ids.ConsumerID) string {
	return fmt.Sprintf(
		"policy narrows to groups but consumer %s accepts api-key auth: group checks do not apply to those callers",
		consumerID)
}

func warnerOver(t *testing.T, gwID ids.GatewayID, consumers []*consumerdomain.Consumer, policies []*domain.Policy) apppolicy.Warner {
	t.Helper()
	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(consumers, nil).Maybe()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(policies, nil).Maybe()
	return apppolicy.NewWarner(repo, consumerRepo, noAPIKeyAuths(t), inertSafeRegistry(t, true))
}

func TestWarner_Overlaps_UnscopedPolicyNeverWarns(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t), noAPIKeyAuths(t), inertSafeRegistry(t, true))

	warnings, err := w.Overlaps(context.Background(), unscopedPolicy(gwID, "trustguard", ids.New[ids.ConsumerKind]()))
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// A scope naming a registry or a tool cannot leave MCP, and saying so is a
// property of the policy: no count of consumers is involved.
func TestWarner_Overlaps_DestinationScopeIsReportedAsMCPOnly(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	p := destinationScopedPolicy(gwID, "trustguard", consumerID)

	w := warnerOver(t, gwID, []*consumerdomain.Consumer{mcpConsumer(gwID, consumerID)}, []*domain.Policy{p})
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{scopeBoundWarning}, warnings)
}

func TestWarner_Overlaps_DormantScopeRunsNowhere(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p := policyWith(gwID, "trustguard", &domain.MCPScope{}, ids.New[ids.ConsumerKind]())

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t), noAPIKeyAuths(t), inertSafeRegistry(t, true))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{dormantWarning}, warnings)
}

// The warning changes nothing about where the policy runs: it only says out
// loud that a policy nobody is attached to and that is not global runs nowhere.
func TestWarner_Overlaps_PolicyWithoutConsumersRunsNowhere(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p := unscopedPolicy(gwID, "trustguard")

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t), noAPIKeyAuths(t), inertSafeRegistry(t, true))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{orphanWarning}, warnings)
}

func TestWarner_Overlaps_GlobalPolicyWithoutConsumersDoesNotWarn(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p := unscopedPolicy(gwID, "trustguard")
	p.Global = true

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t), noAPIKeyAuths(t), inertSafeRegistry(t, true))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestWarner_Overlaps_AttachedConsumers(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	withUnscoped := ids.New[ids.ConsumerKind]()
	clean := ids.New[ids.ConsumerKind]()
	otherSlug := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard", withUnscoped, clean, otherSlug)

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{
			mcpConsumer(gwID, withUnscoped),
			mcpConsumer(gwID, clean),
			mcpConsumer(gwID, otherSlug),
		},
		[]*domain.Policy{
			p,
			unscopedPolicy(gwID, "trustguard", withUnscoped),
			unscopedPolicy(gwID, "rate_limiter", otherSlug),
			scopedPolicy(gwID, "trustguard", clean),
		})

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{overlapWarning(withUnscoped, "trustguard")}, warnings)
}

func TestWarner_Overlaps_DisabledUnscopedDoesNotWarn(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard", consumerID)
	disabled := unscopedPolicy(gwID, "trustguard", consumerID)
	disabled.Enabled = false

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{mcpConsumer(gwID, consumerID)},
		[]*domain.Policy{p, disabled})

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// A disabled policy occupies no level, so writing one never reports a
// collision it is not part of.
func TestWarner_Overlaps_DisabledPolicyDoesNotWarnAboutCollisions(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard", consumerID)
	p.Enabled = false

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t), noAPIKeyAuths(t), inertSafeRegistry(t, true))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// A group-only scope reaches every consumer of the gateway, not only the MCP
// ones: on an LLM consumer the group does not gate, so the policy collapses
// onto the unscoped one of the same slug and only that one runs.
func TestWarner_Overlaps_GlobalGroupScopedReachesEveryConsumerType(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	mcpWithUnscoped := ids.New[ids.ConsumerKind]()
	llmWithUnscoped := ids.New[ids.ConsumerKind]()
	mcpClean := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard")
	p.Global = true

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{
			mcpConsumer(gwID, mcpWithUnscoped),
			llmConsumer(gwID, llmWithUnscoped),
			mcpConsumer(gwID, mcpClean),
		},
		[]*domain.Policy{
			p,
			unscopedPolicy(gwID, "trustguard", mcpWithUnscoped, llmWithUnscoped),
		})

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		overlapWarning(mcpWithUnscoped, "trustguard"),
		coalescedWarning(llmWithUnscoped, "trustguard"),
	}, warnings)
}

// Giving a global policy a group-only scope no longer takes it off non-MCP
// traffic, so there is nothing to report about the consumers it keeps.
func TestWarner_Overlaps_GlobalGroupScopedKeepsNonMCPConsumers(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p := scopedPolicy(gwID, "trustguard")
	p.Global = true

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{
			llmConsumer(gwID, ids.New[ids.ConsumerKind]()),
			llmConsumer(gwID, ids.New[ids.ConsumerKind]()),
		},
		[]*domain.Policy{p})

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// A group-only scope is attachable to an LLM consumer now, and when nothing
// else of that slug runs there it simply runs: no warning.
func TestWarner_Overlaps_GroupScopedOnLLMConsumerAloneDoesNotWarn(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard", consumerID)

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{llmConsumer(gwID, consumerID)},
		[]*domain.Policy{p})

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// The level guard accepts consumer X + groups[finance] next to consumer X +
// groups[engineering]: two distinct levels, and legitimate ones in MCP. On a
// non-MCP consumer both collapse onto (X, all, all) and the load runs neither,
// which until now only showed up in a startup log (RUN-1621, task 3.8).
func TestWarner_Overlaps_TwoGroupScopesCollapseOnANonMCPConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	llmID := ids.New[ids.ConsumerKind]()
	finance := groupScopedPolicy(gwID, "trustguard", "finance", llmID)
	engineering := groupScopedPolicy(gwID, "trustguard", "engineering", llmID)

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{llmConsumer(gwID, llmID)},
		[]*domain.Policy{finance, engineering})

	warnings, err := w.Overlaps(context.Background(), engineering)
	require.NoError(t, err)
	assert.Equal(t, []string{collapsedLevelWarning(llmID, "trustguard")}, warnings)
}

// The same pair on an MCP consumer is two distinct levels that both run, so
// there is nothing to warn about.
func TestWarner_Overlaps_TwoGroupScopesOnAnMCPConsumerDoNotCollapse(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	mcpID := ids.New[ids.ConsumerKind]()
	finance := groupScopedPolicy(gwID, "trustguard", "finance", mcpID)
	engineering := groupScopedPolicy(gwID, "trustguard", "engineering", mcpID)

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{mcpConsumer(gwID, mcpID)},
		[]*domain.Policy{finance, engineering})

	warnings, err := w.Overlaps(context.Background(), engineering)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// A destination scope never leaves MCP, so it cannot collapse onto a
// group-only one on an LLM consumer.
func TestWarner_Overlaps_DestinationScopeDoesNotCollapseWithAGroupScope(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	llmID := ids.New[ids.ConsumerKind]()
	mcpID := ids.New[ids.ConsumerKind]()
	destination := destinationScopedPolicy(gwID, "trustguard", mcpID)
	group := groupScopedPolicy(gwID, "trustguard", "finance", llmID)

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{llmConsumer(gwID, llmID), mcpConsumer(gwID, mcpID)},
		[]*domain.Policy{destination, group})

	warnings, err := w.Overlaps(context.Background(), destination)
	require.NoError(t, err)
	assert.Equal(t, []string{scopeBoundWarning}, warnings)
}

func TestWarner_Overlaps_GlobalUnscopedWarnsEveryReachedConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	a := ids.New[ids.ConsumerKind]()
	b := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard", a, b, a)
	globalUnscoped := unscopedPolicy(gwID, "trustguard")
	globalUnscoped.Global = true

	w := warnerOver(t, gwID,
		[]*consumerdomain.Consumer{mcpConsumer(gwID, a), mcpConsumer(gwID, b)},
		[]*domain.Policy{p, globalUnscoped})

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	require.Len(t, warnings, 2, "duplicate consumer ids collapse to one warning each")
	assert.ElementsMatch(t, []string{overlapWarning(a, "trustguard"), overlapWarning(b, "trustguard")}, warnings)
}

func TestWarner_Overlaps_RepositoryErrorSurfaces(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard", consumerID)
	boom := errors.New("boom")

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*consumerdomain.Consumer{mcpConsumer(gwID, consumerID)}, nil).Once()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, boom).Once()

	w := apppolicy.NewWarner(repo, consumerRepo, noAPIKeyAuths(t), inertSafeRegistry(t, true))
	_, err := w.Overlaps(context.Background(), p)
	assert.ErrorIs(t, err, boom)
}

func TestWarner_Overlaps_ConsumerRepositoryErrorSurfaces(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p := scopedPolicy(gwID, "trustguard", ids.New[ids.ConsumerKind]())
	boom := errors.New("boom")

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, boom).Once()

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumerRepo, noAPIKeyAuths(t), inertSafeRegistry(t, true))
	_, err := w.Overlaps(context.Background(), p)
	assert.ErrorIs(t, err, boom)
}

func TestWarner_OverlapsOnAttach(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()

	tests := []struct {
		name         string
		gatewayID    ids.GatewayID
		consumerType consumerdomain.Type
		policy       *domain.Policy
		others       []*domain.Policy
		want         []string
	}{
		{
			name:         "mcp consumer already runs the slug unscoped",
			gatewayID:    gwID,
			consumerType: consumerdomain.TypeMCP,
			policy:       scopedPolicy(gwID, "trustguard", consumerID),
			others:       []*domain.Policy{unscopedPolicy(gwID, "trustguard", consumerID)},
			want:         []string{overlapWarning(consumerID, "trustguard")},
		},
		{
			name:         "llm consumer already runs the slug unscoped",
			gatewayID:    gwID,
			consumerType: consumerdomain.TypeLLM,
			policy:       scopedPolicy(gwID, "trustguard", consumerID),
			others:       []*domain.Policy{unscopedPolicy(gwID, "trustguard", consumerID)},
			want:         []string{coalescedWarning(consumerID, "trustguard")},
		},
		{
			name:         "llm consumer already runs the slug under another group scope",
			gatewayID:    gwID,
			consumerType: consumerdomain.TypeLLM,
			policy:       groupScopedPolicy(gwID, "trustguard", "engineering", consumerID),
			others:       []*domain.Policy{groupScopedPolicy(gwID, "trustguard", "finance", consumerID)},
			want:         []string{collapsedLevelWarning(consumerID, "trustguard")},
		},
		{
			name:         "consumer runs a different slug",
			gatewayID:    gwID,
			consumerType: consumerdomain.TypeMCP,
			policy:       scopedPolicy(gwID, "trustguard", consumerID),
			others:       []*domain.Policy{unscopedPolicy(gwID, "rate_limiter", consumerID)},
		},
		{
			name:         "attached policy has no scope",
			gatewayID:    gwID,
			consumerType: consumerdomain.TypeMCP,
			policy:       unscopedPolicy(gwID, "trustguard", consumerID),
			others:       []*domain.Policy{unscopedPolicy(gwID, "trustguard", consumerID)},
		},
		{
			name:         "attached policy is a tombstone",
			gatewayID:    gwID,
			consumerType: consumerdomain.TypeMCP,
			policy:       policyWith(gwID, "trustguard", &domain.MCPScope{}, consumerID),
			others:       []*domain.Policy{unscopedPolicy(gwID, "trustguard", consumerID)},
		},
		{
			name:         "policy from another gateway",
			gatewayID:    ids.New[ids.GatewayKind](),
			consumerType: consumerdomain.TypeMCP,
			policy:       scopedPolicy(gwID, "trustguard", consumerID),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, tt.policy.ID).Return(tt.policy, nil).Once()
			if tt.others != nil {
				repo.EXPECT().ListByGateway(mock.Anything, gwID).
					Return(append([]*domain.Policy{tt.policy}, tt.others...), nil).Maybe()
			}
			consumerRepo := consumermocks.NewRepository(t)
			consumerRepo.EXPECT().FindByID(mock.Anything, consumerID).
				Return(&consumerdomain.Consumer{ID: consumerID, GatewayID: gwID, Type: tt.consumerType}, nil).Maybe()

			w := apppolicy.NewWarner(repo, consumerRepo, noAPIKeyAuths(t), inertSafeRegistry(t, true))
			warnings, err := w.OverlapsOnAttach(context.Background(), tt.gatewayID, consumerID, tt.policy.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.want, warnings)
		})
	}
}

// The promotion of a group-scoped policy on a plugin that gates by name is
// saved and then runs nowhere but MCP: it skips the attach, which is where the
// same case is a 422, so the warning is the only thing that says so
// (RUN-1621, task 5.7).
func TestWarner_Overlaps_GlobalGroupScopeOnANameGatingPluginWarns(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p := groupScopedPolicy(gwID, "tool_allowlist", "Finanzas")
	p.Global = true

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Maybe()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Policy{p}, nil).Maybe()

	w := apppolicy.NewWarner(repo, consumerRepo, noAPIKeyAuths(t), inertSafeRegistry(t, false))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{inertUnsafeGlobalWarning("tool_allowlist")}, warnings)
}

func TestWarner_Overlaps_GlobalGroupScopeOnAnInertSafePluginDoesNotWarn(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	p := groupScopedPolicy(gwID, "trustguard", "Finanzas")
	p.Global = true

	w := warnerOver(t, gwID, []*consumerdomain.Consumer{mcpConsumer(gwID, consumerID)}, []*domain.Policy{p})
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// A group scope that is not global still goes through the attach, which
// refuses it on a non-MCP consumer, so the warning would be noise.
func TestWarner_Overlaps_NonGlobalGroupScopeOnANameGatingPluginDoesNotWarn(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	p := groupScopedPolicy(gwID, "tool_allowlist", "Finanzas", consumerID)

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*consumerdomain.Consumer{mcpConsumer(gwID, consumerID)}, nil).Maybe()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Policy{p}, nil).Maybe()

	w := apppolicy.NewWarner(repo, consumerRepo, noAPIKeyAuths(t), inertSafeRegistry(t, false))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func inertUnsafeGlobalWarning(slug string) string {
	return fmt.Sprintf("policy is global and its scope narrows by group alone, but plugin %s has not opted into "+
		"running where the scope is inert: it runs on MCP traffic only, never on the LLM or A2A plane", slug)
}

func mcpConsumerWithAuths(gwID ids.GatewayID, id ids.ConsumerID, authIDs ...ids.AuthID) *consumerdomain.Consumer {
	c := mcpConsumer(gwID, id)
	c.AuthIDs = authIDs
	return c
}

func llmConsumerWithAuths(gwID ids.GatewayID, id ids.ConsumerID, authIDs ...ids.AuthID) *consumerdomain.Consumer {
	c := llmConsumer(gwID, id)
	c.AuthIDs = authIDs
	return c
}

func warnerOverAuths(
	t *testing.T,
	gwID ids.GatewayID,
	consumers []*consumerdomain.Consumer,
	policies []*domain.Policy,
	auths authdomain.Repository,
) apppolicy.Warner {
	t.Helper()
	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(consumers, nil).Maybe()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(policies, nil).Maybe()
	return apppolicy.NewWarner(repo, consumerRepo, auths, inertSafeRegistry(t, true))
}

// A policy narrowing to groups is not an access control against a consumer
// that admits api keys: for those callers the principal is inert and the
// policy runs. The warning names the consumers so the operator can drop the
// credential or accept the reach (RUN-1621, rule 5.2).
func TestWarner_Overlaps_GroupScopeNamesTheConsumersThatAcceptAPIKeys(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	withKey, withoutKey := ids.New[ids.ConsumerKind](), ids.New[ids.ConsumerKind]()
	keyID, tokenID := ids.New[ids.AuthKind](), ids.New[ids.AuthKind]()
	p := groupScopedPolicy(gwID, "trustguard", "Finanzas", withKey, withoutKey)

	w := warnerOverAuths(t, gwID,
		[]*consumerdomain.Consumer{
			mcpConsumerWithAuths(gwID, withKey, keyID),
			mcpConsumerWithAuths(gwID, withoutKey, tokenID),
		},
		[]*domain.Policy{p},
		apiKeyAuths(t, gwID, keyID),
	)

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{apiKeyIgnoresGroupsWarning(withKey)}, warnings,
		"only the consumer whose auth is an api key is named")
}

func TestWarner_Overlaps_APIKeyWarningCoversDestinationScopesToo(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	keyID := ids.New[ids.AuthKind]()
	p := policyWith(gwID, "trustguard", &domain.MCPScope{
		RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()},
		Groups:      []string{"Finanzas"},
	}, consumerID)

	w := warnerOverAuths(t, gwID,
		[]*consumerdomain.Consumer{mcpConsumerWithAuths(gwID, consumerID, keyID)},
		[]*domain.Policy{p},
		apiKeyAuths(t, gwID, keyID),
	)

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{scopeBoundWarning, apiKeyIgnoresGroupsWarning(consumerID)}, warnings,
		"narrowing the destination does not restore the group check for an api-key caller")
}

// The exception direction is unaffected: an api-key caller carries no groups,
// so it never fell in except_groups and nothing about it changed.
func TestWarner_Overlaps_ExceptGroupsScopeDoesNotWarnAboutAPIKeys(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	keyID := ids.New[ids.AuthKind]()
	p := policyWith(gwID, "trustguard", &domain.MCPScope{ExceptGroups: []string{"Finanzas"}}, consumerID)

	w := warnerOverAuths(t, gwID,
		[]*consumerdomain.Consumer{mcpConsumerWithAuths(gwID, consumerID, keyID)},
		[]*domain.Policy{p},
		apiKeyAuths(t, gwID, keyID),
	)

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// Outside MCP the principal dimension is inert for every caller, whatever the
// credential, which the coalescence warnings already say. Naming the
// credential there would attribute it to the wrong cause.
func TestWarner_Overlaps_APIKeyWarningIsMCPOnly(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	keyID := ids.New[ids.AuthKind]()
	p := groupScopedPolicy(gwID, "trustguard", "Finanzas", consumerID)

	w := warnerOverAuths(t, gwID,
		[]*consumerdomain.Consumer{llmConsumerWithAuths(gwID, consumerID, keyID)},
		[]*domain.Policy{p},
		apiKeyAuths(t, gwID, keyID),
	)

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

// A disabled api key authenticates nobody, so it does not widen anything.
func TestWarner_Overlaps_DisabledAPIKeyDoesNotWarn(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	keyID := ids.New[ids.AuthKind]()
	p := groupScopedPolicy(gwID, "trustguard", "Finanzas", consumerID)

	w := warnerOverAuths(t, gwID,
		[]*consumerdomain.Consumer{mcpConsumerWithAuths(gwID, consumerID, keyID)},
		[]*domain.Policy{p},
		apiKeyAuths(t, gwID),
	)

	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestWarner_OverlapsOnAttach_NamesTheAPIKeyConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	keyID := ids.New[ids.AuthKind]()
	p := groupScopedPolicy(gwID, "trustguard", "Finanzas")

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, p.ID).Return(p, nil).Once()
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Policy{p}, nil).Maybe()
	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().FindByID(mock.Anything, consumerID).
		Return(mcpConsumerWithAuths(gwID, consumerID, keyID), nil).Once()

	w := apppolicy.NewWarner(repo, consumerRepo, apiKeyAuths(t, gwID, keyID), inertSafeRegistry(t, true))
	warnings, err := w.OverlapsOnAttach(context.Background(), gwID, consumerID, p.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{apiKeyIgnoresGroupsWarning(consumerID)}, warnings)
}

func TestWarner_Overlaps_AuthRepositoryErrorSurfaces(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	p := groupScopedPolicy(gwID, "trustguard", "Finanzas", consumerID)
	boom := errors.New("boom")

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByGateway(mock.Anything, gwID).
		Return([]*consumerdomain.Consumer{mcpConsumer(gwID, consumerID)}, nil).Once()
	auths := authmocks.NewRepository(t)
	auths.EXPECT().ListEnabledByGatewayAndType(mock.Anything, gwID, authdomain.TypeAPIKey).
		Return(nil, boom).Once()

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumerRepo, auths, inertSafeRegistry(t, true))
	_, err := w.Overlaps(context.Background(), p)
	assert.ErrorIs(t, err, boom)
}
