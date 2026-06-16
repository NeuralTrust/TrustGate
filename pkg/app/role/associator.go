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
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=Associator --dir=. --output=./mocks --filename=role_associator_mock.go --case=underscore --with-expecter
type Associator interface {
	AttachRegistry(ctx context.Context, gatewayID ids.GatewayID, roleID ids.RoleID, registryID ids.RegistryID) error
	DetachRegistry(ctx context.Context, gatewayID ids.GatewayID, roleID ids.RoleID, registryID ids.RegistryID) error
}

var _ Associator = (*associator)(nil)

type associator struct {
	repo         domain.Repository
	registryRepo registrydomain.Repository
	memoryCache  *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
}

func NewAssociator(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Associator {
	return &associator{
		repo:         repo,
		registryRepo: registryRepo,
		memoryCache:  manager.GetTTLMap(cache.RoleTTLName),
		publisher:    publisher,
		logger:       logger,
	}
}

func (a *associator) AttachRegistry(ctx context.Context, gatewayID ids.GatewayID, roleID ids.RoleID, registryID ids.RegistryID) error {
	role, err := a.roleInGateway(ctx, gatewayID, roleID)
	if err != nil {
		return err
	}
	if err := a.registryInGateway(ctx, gatewayID, registryID); err != nil {
		return err
	}
	if err := a.repo.AttachRegistry(ctx, roleID, registryID); err != nil {
		return err
	}
	a.invalidate(ctx, role)
	return nil
}

func (a *associator) DetachRegistry(ctx context.Context, gatewayID ids.GatewayID, roleID ids.RoleID, registryID ids.RegistryID) error {
	role, err := a.repo.DetachRegistryIfUnreferenced(ctx, gatewayID, roleID, registryID)
	if err != nil {
		return err
	}
	a.invalidate(ctx, role)
	return nil
}

func (a *associator) roleInGateway(ctx context.Context, gatewayID ids.GatewayID, roleID ids.RoleID) (*domain.Role, error) {
	role, err := a.repo.FindByID(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if role.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	return role, nil
}

func (a *associator) registryInGateway(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error {
	reg, err := a.registryRepo.FindByID(ctx, registryID)
	if err != nil {
		return err
	}
	if reg.GatewayID != gatewayID {
		return registrydomain.ErrNotFound
	}
	return nil
}

func (a *associator) invalidate(ctx context.Context, role *domain.Role) {
	a.memoryCache.Delete(role.ID.String())
	publishGatewayDataInvalidation(ctx, a.publisher, a.logger, role.GatewayID)
}
