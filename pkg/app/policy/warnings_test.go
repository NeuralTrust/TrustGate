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

func scopedPolicy(gwID ids.GatewayID, slug string, consumers ...ids.ConsumerID) *domain.Policy {
	return &domain.Policy{
		ID:          ids.New[ids.PolicyKind](),
		GatewayID:   gwID,
		Slug:        slug,
		Enabled:     true,
		ConsumerIDs: consumers,
		MCPScope:    &domain.MCPScope{Groups: []string{"Finanzas"}},
	}
}

func unscopedPolicy(gwID ids.GatewayID, slug string, consumers ...ids.ConsumerID) *domain.Policy {
	return &domain.Policy{
		ID:          ids.New[ids.PolicyKind](),
		GatewayID:   gwID,
		Slug:        slug,
		Enabled:     true,
		ConsumerIDs: consumers,
	}
}

func overlapWarning(consumerID ids.ConsumerID, slug string) string {
	return fmt.Sprintf("consumer %s already runs plugin %s without scope", consumerID, slug)
}

func TestWarner_Overlaps_UnscopedPolicyNeverWarns(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	w := apppolicy.NewWarner(repomocks.NewRepository(t), consumermocks.NewRepository(t))

	warnings, err := w.Overlaps(context.Background(), unscopedPolicy(gwID, "trustguard", ids.New[ids.ConsumerKind]()))
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

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Policy{
		p,
		unscopedPolicy(gwID, "trustguard", withUnscoped),
		unscopedPolicy(gwID, "rate_limiter", otherSlug),
		scopedPolicy(gwID, "trustguard", clean),
	}, nil).Once()

	w := apppolicy.NewWarner(repo, consumermocks.NewRepository(t))
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

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Policy{p, disabled}, nil).Once()

	w := apppolicy.NewWarner(repo, consumermocks.NewRepository(t))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestWarner_Overlaps_GlobalPolicyReachesMCPConsumersOnly(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	mcpWithUnscoped := ids.New[ids.ConsumerKind]()
	llmWithUnscoped := ids.New[ids.ConsumerKind]()
	mcpClean := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard")
	p.Global = true

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*consumerdomain.Consumer{
		{ID: mcpWithUnscoped, GatewayID: gwID, Type: consumerdomain.TypeMCP},
		{ID: llmWithUnscoped, GatewayID: gwID, Type: consumerdomain.TypeLLM},
		{ID: mcpClean, GatewayID: gwID, Type: consumerdomain.TypeMCP},
	}, nil).Once()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Policy{
		p,
		unscopedPolicy(gwID, "trustguard", mcpWithUnscoped, llmWithUnscoped),
	}, nil).Once()

	w := apppolicy.NewWarner(repo, consumers)
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, []string{overlapWarning(mcpWithUnscoped, "trustguard")}, warnings)
}

func TestWarner_Overlaps_GlobalUnscopedWarnsEveryReachedConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	a := ids.New[ids.ConsumerKind]()
	b := ids.New[ids.ConsumerKind]()
	p := scopedPolicy(gwID, "trustguard", a, b, a)
	globalUnscoped := unscopedPolicy(gwID, "trustguard")
	globalUnscoped.Global = true

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Policy{p, globalUnscoped}, nil).Once()

	w := apppolicy.NewWarner(repo, consumermocks.NewRepository(t))
	warnings, err := w.Overlaps(context.Background(), p)
	require.NoError(t, err)
	require.Len(t, warnings, 2, "duplicate consumer ids collapse to one warning each")
	assert.ElementsMatch(t, []string{overlapWarning(a, "trustguard"), overlapWarning(b, "trustguard")}, warnings)
}

func TestWarner_Overlaps_RepositoryErrorSurfaces(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	p := scopedPolicy(gwID, "trustguard", ids.New[ids.ConsumerKind]())
	boom := errors.New("boom")

	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, boom).Once()

	w := apppolicy.NewWarner(repo, consumermocks.NewRepository(t))
	_, err := w.Overlaps(context.Background(), p)
	assert.ErrorIs(t, err, boom)
}

func TestWarner_OverlapsOnAttach(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()

	tests := []struct {
		name      string
		gatewayID ids.GatewayID
		policy    *domain.Policy
		others    []*domain.Policy
		want      []string
	}{
		{
			name:      "consumer already runs the slug unscoped",
			gatewayID: gwID,
			policy:    scopedPolicy(gwID, "trustguard", consumerID),
			others:    []*domain.Policy{unscopedPolicy(gwID, "trustguard", consumerID)},
			want:      []string{overlapWarning(consumerID, "trustguard")},
		},
		{
			name:      "consumer runs a different slug",
			gatewayID: gwID,
			policy:    scopedPolicy(gwID, "trustguard", consumerID),
			others:    []*domain.Policy{unscopedPolicy(gwID, "rate_limiter", consumerID)},
		},
		{
			name:      "attached policy has no scope",
			gatewayID: gwID,
			policy:    unscopedPolicy(gwID, "trustguard", consumerID),
			others:    []*domain.Policy{unscopedPolicy(gwID, "trustguard", consumerID)},
		},
		{
			name:      "policy from another gateway",
			gatewayID: ids.New[ids.GatewayKind](),
			policy:    scopedPolicy(gwID, "trustguard", consumerID),
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

			w := apppolicy.NewWarner(repo, consumermocks.NewRepository(t))
			warnings, err := w.OverlapsOnAttach(context.Background(), tt.gatewayID, consumerID, tt.policy.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.want, warnings)
		})
	}
}
