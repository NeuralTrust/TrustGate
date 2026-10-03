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
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type countingSignaler struct{ n int }

func (s *countingSignaler) Signal(context.Context) { s.n++ }

func TestLabelUpdater_ReplacesTheLabels(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
	existing.Labels = []trafficlabel.Label{{ID: "old", Name: "Old", Instructions: "x"}}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		UpdateLabels(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.ID == existing.ID && len(c.Labels) == 1 && c.Labels[0].ID == "l-1" && c.Labels[0].Name == "Billing"
		})).
		Return(nil).
		Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()
	signaler := &countingSignaler{}

	updater := appconsumer.NewLabelUpdater(repo, newCacheManager(), publisher, newTestLogger(), signaler)
	got, err := updater.UpdateLabels(context.Background(), appconsumer.UpdateLabelsInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Labels:    []trafficlabel.Label{{ID: " l-1 ", Name: " Billing ", Instructions: "refunds"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []trafficlabel.Label{{ID: "l-1", Name: "Billing", Instructions: "refunds"}}, got.Labels)
	assert.Equal(t, 1, signaler.n, "the data planes get the new labels with the next snapshot")
}

func TestLabelUpdater_ClearsTheLabels(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
	existing.Labels = []trafficlabel.Label{{ID: "old", Name: "Old", Instructions: "x"}}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		UpdateLabels(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool { return c.Labels == nil })).
		Return(nil).
		Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appconsumer.NewLabelUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.UpdateLabels(context.Background(), appconsumer.UpdateLabelsInput{
		ID: existing.ID, GatewayID: gwID, Labels: []trafficlabel.Label{},
	})
	require.NoError(t, err)
	assert.Empty(t, got.Labels)
}

func TestLabelUpdater_Rejects(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	valid := []trafficlabel.Label{{ID: "l-1", Name: "Billing", Instructions: "refunds"}}

	tests := []struct {
		name    string
		mutate  func(c *domain.Consumer)
		gateway ids.GatewayID
		labels  []trafficlabel.Label
		want    error
	}{
		{name: "MCP consumer", mutate: func(c *domain.Consumer) { c.Type = domain.TypeMCP }, gateway: gwID, labels: valid, want: commonerrors.ErrValidation},
		{name: "A2A consumer", mutate: func(c *domain.Consumer) { c.Type = domain.TypeA2A }, gateway: gwID, labels: valid, want: commonerrors.ErrValidation},
		{name: "another gateway", gateway: ids.New[ids.GatewayKind](), labels: valid, want: domain.ErrNotFound},
		{name: "invalid labels", gateway: gwID, labels: []trafficlabel.Label{{ID: "l-1", Name: "", Instructions: "x"}}, want: commonerrors.ErrValidation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
			if tt.mutate != nil {
				tt.mutate(existing)
			}
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

			updater := appconsumer.NewLabelUpdater(repo, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
			_, err := updater.UpdateLabels(context.Background(), appconsumer.UpdateLabelsInput{
				ID: existing.ID, GatewayID: tt.gateway, Labels: tt.labels,
			})
			require.True(t, errors.Is(err, tt.want), "error = %v, want %v", err, tt.want)
		})
	}
}

func TestLabelUpdater_ClearingAnMCPConsumerIsAllowed(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
	existing.Type = domain.TypeMCP

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().UpdateLabels(mock.Anything, mock.Anything).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appconsumer.NewLabelUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.UpdateLabels(context.Background(), appconsumer.UpdateLabelsInput{ID: existing.ID, GatewayID: gwID, Labels: nil})
	require.NoError(t, err, "the app clears a consumer's labels without checking its type first")
}

func TestLabelUpdater_PropagatesRepositoryErrors(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
	boom := errors.New("db down")

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().UpdateLabels(mock.Anything, mock.Anything).Return(boom).Once()

	updater := appconsumer.NewLabelUpdater(repo, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
	_, err := updater.UpdateLabels(context.Background(), appconsumer.UpdateLabelsInput{
		ID: existing.ID, GatewayID: gwID, Labels: []trafficlabel.Label{{ID: "l-1", Name: "Billing", Instructions: "refunds"}},
	})
	require.ErrorIs(t, err, boom)
}

func TestUpdater_Update_LeavesLabelsUntouched(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)
	labels := []trafficlabel.Label{{ID: "l-1", Name: "Billing", Instructions: "refunds"}}
	existing.Labels = labels

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.Name == "paused" && !c.Active && len(c.Labels) == 1 && c.Labels[0].ID == "l-1"
		}), mock.Anything, mock.Anything).
		Return(nil).
		Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("paused"),
		Active:    ptr(false),
	})
	require.NoError(t, err)
	assert.Equal(t, labels, got.Labels, "a generic update without labels keeps the stored ones")
}
