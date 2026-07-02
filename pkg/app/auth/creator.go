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

type CreateInput struct {
	GatewayID ids.GatewayID
	Name      string
	Type      domain.Type
	Enabled   bool
	Config    domain.Config
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=auth_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Auth, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	keyCache    *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
}

func NewCreator(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, signaler configsyncport.SnapshotSignaler) Creator {
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.AuthTTLName),
		keyCache:    manager.GetTTLMap(cache.AuthKeyTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Auth, error) {
	a, err := c.build(in)
	if err != nil {
		return nil, err
	}
	if err := ensureNoOAuth2Conflict(ctx, c.repo, a); err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, a); err != nil {
		return nil, err
	}
	c.memoryCache.Set(a.ID.String(), a)
	if a.KeyHash != "" {
		c.keyCache.Set(a.KeyHash, a)
	}
	publishGatewayDataInvalidation(ctx, c.publisher, c.logger, a.GatewayID)
	if c.signaler != nil {
		c.signaler.Signal(ctx)
	}
	return a, nil
}

func (c *creator) build(in CreateInput) (*domain.Auth, error) {
	if in.Type == domain.TypeAPIKey {
		return domain.NewAPIKeyAuth(in.GatewayID, in.Name, in.Enabled)
	}
	return domain.NewAuth(in.GatewayID, in.Name, in.Type, in.Enabled, in.Config)
}
