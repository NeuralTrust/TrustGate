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

func labelSet(id, name string) trafficlabel.LabelSet {
	return trafficlabel.LabelSet{
		ID:           id,
		Name:         name,
		Instructions: "overall mood",
		Labels:       []trafficlabel.Label{{Name: "positive", Description: "happy"}, {Name: "negative"}},
	}
}

func TestLabelSetUpdater_ReplacesTheLabelSets(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
	existing.LabelSets = []trafficlabel.LabelSet{labelSet("old", "Old")}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		UpdateLabelSets(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.ID == existing.ID && len(c.LabelSets) == 1 && c.LabelSets[0].ID == "set-1" && c.LabelSets[0].Name == "Sentiment"
		})).
		Return(nil).
		Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()
	signaler := &countingSignaler{}

	updater := appconsumer.NewLabelSetUpdater(repo, newCacheManager(), publisher, newTestLogger(), signaler)
	got, err := updater.UpdateLabelSets(context.Background(), appconsumer.UpdateLabelSetsInput{
		ID:        existing.ID,
		GatewayID: gwID,
		LabelSets: []trafficlabel.LabelSet{labelSet(" set-1 ", " Sentiment ")},
	})
	require.NoError(t, err)
	assert.Equal(t, []trafficlabel.LabelSet{labelSet("set-1", "Sentiment")}, got.LabelSets)
	assert.Equal(t, 1, signaler.n, "the data planes get the new label sets with the next snapshot")
}

func TestLabelSetUpdater_ClearsTheLabelSets(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
	existing.LabelSets = []trafficlabel.LabelSet{labelSet("old", "Old")}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		UpdateLabelSets(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool { return c.LabelSets == nil })).
		Return(nil).
		Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appconsumer.NewLabelSetUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.UpdateLabelSets(context.Background(), appconsumer.UpdateLabelSetsInput{
		ID: existing.ID, GatewayID: gwID, LabelSets: []trafficlabel.LabelSet{},
	})
	require.NoError(t, err)
	assert.Empty(t, got.LabelSets)
}

func TestLabelSetUpdater_Rejects(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	valid := []trafficlabel.LabelSet{labelSet("set-1", "Sentiment")}
	oneLabel := labelSet("set-1", "Sentiment")
	oneLabel.Labels = oneLabel.Labels[:1]

	tests := []struct {
		name    string
		mutate  func(c *domain.Consumer)
		gateway ids.GatewayID
		sets    []trafficlabel.LabelSet
		want    error
	}{
		{name: "MCP consumer", mutate: func(c *domain.Consumer) { c.Type = domain.TypeMCP }, gateway: gwID, sets: valid, want: commonerrors.ErrValidation},
		{name: "A2A consumer", mutate: func(c *domain.Consumer) { c.Type = domain.TypeA2A }, gateway: gwID, sets: valid, want: commonerrors.ErrValidation},
		{name: "another gateway", gateway: ids.New[ids.GatewayKind](), sets: valid, want: domain.ErrNotFound},
		{name: "invalid label set", gateway: gwID, sets: []trafficlabel.LabelSet{oneLabel}, want: commonerrors.ErrValidation},
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

			updater := appconsumer.NewLabelSetUpdater(repo, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
			_, err := updater.UpdateLabelSets(context.Background(), appconsumer.UpdateLabelSetsInput{
				ID: existing.ID, GatewayID: tt.gateway, LabelSets: tt.sets,
			})
			require.True(t, errors.Is(err, tt.want), "error = %v, want %v", err, tt.want)
		})
	}
}

func TestLabelSetUpdater_ClearingAnMCPConsumerIsAllowed(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
	existing.Type = domain.TypeMCP

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().UpdateLabelSets(mock.Anything, mock.Anything).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appconsumer.NewLabelSetUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.UpdateLabelSets(context.Background(), appconsumer.UpdateLabelSetsInput{ID: existing.ID, GatewayID: gwID, LabelSets: nil})
	require.NoError(t, err, "the app clears a consumer's label sets without checking its type first")
}

func TestLabelSetUpdater_PropagatesRepositoryErrors(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())
	boom := errors.New("db down")

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().UpdateLabelSets(mock.Anything, mock.Anything).Return(boom).Once()

	updater := appconsumer.NewLabelSetUpdater(repo, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
	_, err := updater.UpdateLabelSets(context.Background(), appconsumer.UpdateLabelSetsInput{
		ID: existing.ID, GatewayID: gwID, LabelSets: []trafficlabel.LabelSet{labelSet("set-1", "Sentiment")},
	})
	require.ErrorIs(t, err, boom)
}

func TestUpdater_Update_LeavesLabelSetsUntouched(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)
	sets := []trafficlabel.LabelSet{labelSet("set-1", "Sentiment")}
	existing.LabelSets = sets

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.Name == "paused" && !c.Active && len(c.LabelSets) == 1 && c.LabelSets[0].ID == "set-1"
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
	assert.Equal(t, sets, got.LabelSets, "a generic update keeps the stored label sets")
}
