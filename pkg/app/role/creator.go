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

package role

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID  ids.GatewayID
	Name       string
	IDPMapping json.RawMessage
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=role_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Role, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewCreator(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Creator {
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RoleTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Role, error) {
	role, err := domain.New(domain.CreateParams{
		GatewayID:  in.GatewayID,
		Name:       in.Name,
		IDPMapping: in.IDPMapping,
	})
	if err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, role); err != nil {
		return nil, err
	}
	c.memoryCache.Set(role.ID.String(), role)
	publishGatewayDataInvalidation(ctx, c.publisher, c.logger, role.GatewayID)
	return role, nil
}
