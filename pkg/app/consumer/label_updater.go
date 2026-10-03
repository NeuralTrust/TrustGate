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

package consumer

import (
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type UpdateLabelsInput struct {
	ID        ids.ConsumerID
	GatewayID ids.GatewayID
	// Labels replaces the whole label list; an empty list clears it.
	Labels []trafficlabel.Label
}

//go:generate mockery --name=LabelUpdater --dir=. --output=./mocks --filename=consumer_label_updater_mock.go --case=underscore --with-expecter
type LabelUpdater interface {
	UpdateLabels(ctx context.Context, in UpdateLabelsInput) (*domain.Consumer, error)
}

var _ LabelUpdater = (*labelUpdater)(nil)

type labelUpdater struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
}

func NewLabelUpdater(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
) LabelUpdater {
	return &labelUpdater{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
	}
}

func (u *labelUpdater) UpdateLabels(ctx context.Context, in UpdateLabelsInput) (*domain.Consumer, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !in.GatewayID.IsNil() && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrNotFound
	}
	if err := existing.SetLabels(in.Labels); err != nil {
		return nil, err
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := u.repo.UpdateLabels(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	invalidation.GatewayData(ctx, u.publisher, u.logger, existing.GatewayID)
	if u.signaler != nil {
		u.signaler.Signal(ctx)
	}
	return existing, nil
}
