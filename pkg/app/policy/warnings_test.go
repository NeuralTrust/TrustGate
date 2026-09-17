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

	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
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

func warnerOver(t *testing.T, gwID ids.GatewayID, consumers []*consumerdomain.Consumer, policies []*domain.Policy) apppolicy.Warner {
	t.Helper()
	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(consumers, nil).Maybe()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(policies, nil).Maybe()
	return apppolicy.NewWarner(repo, consumerRepo)
}

func TestWarner_Overlaps_UnscopedPolicyNeverWarns(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t))

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

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t))
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

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{orphanWarning}, warnings)
}

func TestWarner_Overlaps_GlobalPolicyWithoutConsumersDoesNotWarn(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p := unscopedPolicy(gwID, "trustguard")
	p.Global = true

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t))
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

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t))
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

	w := apppolicy.NewWarner(repo, consumerRepo)
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

	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumerRepo)
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

			w := apppolicy.NewWarner(repo, consumerRepo)
			warnings, err := w.OverlapsOnAttach(context.Background(), tt.gatewayID, consumerID, tt.policy.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.want, warnings)
		})
	}
}
