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
	"errors"
	"fmt"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID       ids.GatewayID
	Name            string
	Type            domain.Type
	RoutingMode     domain.RoutingMode
	LBConfig        *domain.LBConfig
	Headers         map[string]string
	Active          *bool
	Fallback        *domain.Fallback
	RegistryIDs     []ids.RegistryID
	RegistryWeights map[ids.RegistryID]int
	RoleIDs         []ids.RoleID
	ModelPolicies   domain.ModelPolicies
	MCP             *domain.MCPPolicy
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=consumer_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Consumer, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo         domain.Repository
	registryRepo registrydomain.Repository
	roleRepo     roledomain.Repository
	memoryCache  *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
}

func NewCreator(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	roleRepo roledomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Creator {
	return &creator{
		repo:         repo,
		registryRepo: registryRepo,
		roleRepo:     roleRepo,
		memoryCache:  manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:    publisher,
		logger:       logger,
	}
}

const maxSlugCollisionRetries = 3

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Consumer, error) {
	cons, err := domain.New(domain.CreateParams{
		GatewayID:       in.GatewayID,
		Name:            in.Name,
		Type:            in.Type,
		RoutingMode:     in.RoutingMode,
		LBConfig:        in.LBConfig,
		Headers:         in.Headers,
		Active:          in.Active,
		Fallback:        in.Fallback,
		RegistryIDs:     in.RegistryIDs,
		RegistryWeights: in.RegistryWeights,
		RoleIDs:         in.RoleIDs,
		ModelPolicies:   in.ModelPolicies,
		MCP:             in.MCP,
	})
	if err != nil {
		return nil, err
	}
	if err := validateRegistryRefsAssociated(cons); err != nil {
		return nil, err
	}
	if err := c.ensureRegistriesInGateway(ctx, in.GatewayID, in.RegistryIDs); err != nil {
		return nil, err
	}
	if err := c.ensureRolesInGateway(ctx, in.GatewayID, in.RoleIDs); err != nil {
		return nil, err
	}
	if err := c.saveWithSlugRetry(ctx, cons); err != nil {
		return nil, err
	}
	c.memoryCache.Set(cons.ID.String(), cons)
	publishGatewayDataInvalidation(ctx, c.publisher, c.logger, cons.GatewayID)
	return cons, nil
}

func (c *creator) saveWithSlugRetry(ctx context.Context, cons *domain.Consumer) error {
	for attempt := 0; ; attempt++ {
		err := c.repo.Save(ctx, cons)
		if !errors.Is(err, domain.ErrSlugAlreadyExists) || attempt == maxSlugCollisionRetries-1 {
			return err
		}
		slug, slugErr := domain.NewSlug()
		if slugErr != nil {
			return slugErr
		}
		cons.Slug = slug
	}
}

func (c *creator) ensureRegistriesInGateway(ctx context.Context, gatewayID ids.GatewayID, registryIDs []ids.RegistryID) error {
	if len(registryIDs) == 0 {
		return nil
	}
	found, err := c.registryRepo.FindByIDs(ctx, gatewayID, registryIDs)
	if err != nil {
		return err
	}
	if len(found) != len(registryIDs) {
		return fmt.Errorf("%w: one or more registries do not belong to the gateway", registrydomain.ErrInvalidRegistryID)
	}
	return nil
}

func (c *creator) ensureRolesInGateway(ctx context.Context, gatewayID ids.GatewayID, roleIDs []ids.RoleID) error {
	if len(roleIDs) == 0 {
		return nil
	}
	found, err := c.roleRepo.FindByIDs(ctx, gatewayID, roleIDs)
	if err != nil {
		return err
	}
	if len(found) != len(roleIDs) {
		return fmt.Errorf("%w: one or more roles do not belong to the gateway", roledomain.ErrInvalidRoleID)
	}
	return nil
}
