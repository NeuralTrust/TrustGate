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

package auth

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=Deleter --dir=. --output=./mocks --filename=auth_deleter_mock.go --case=underscore --with-expecter
type Deleter interface {
	Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.AuthID) error
}

var _ Deleter = (*deleter)(nil)

type deleter struct {
	repo         domain.Repository
	consumerRepo consumerAuthRefs
	memoryCache  *cache.TTLMap
	keyCache     *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
	signaler     configsyncport.SnapshotSignaler
}

func NewDeleter(
	repo domain.Repository,
	consumerRepo consumerAuthRefs,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
) Deleter {
	return &deleter{
		repo:         repo,
		consumerRepo: consumerRepo,
		memoryCache:  manager.GetTTLMap(cache.AuthTTLName),
		keyCache:     manager.GetTTLMap(cache.AuthKeyTTLName),
		publisher:    publisher,
		logger:       logger,
		signaler:     signaler,
	}
}

func (d *deleter) Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.AuthID) error {
	existing, err := d.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if existing.GatewayID != gatewayID {
		return domain.ErrNotFound
	}
	if err := guardAndDetachAuth(ctx, d.consumerRepo, d.repo, id); err != nil {
		return err
	}
	if err := d.repo.Delete(ctx, gatewayID, id); err != nil {
		return err
	}
	d.memoryCache.Delete(id.String())
	if existing.KeyHash != "" {
		d.keyCache.Delete(existing.KeyHash)
	}
	publishGatewayDataInvalidation(ctx, d.publisher, d.logger, existing.GatewayID)
	if d.signaler != nil {
		d.signaler.Signal(ctx)
	}
	return nil
}
