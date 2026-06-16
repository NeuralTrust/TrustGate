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

package registry

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

type UpdateInput struct {
	ID              ids.RegistryID
	GatewayID       ids.GatewayID
	Name            *string
	Provider        *string
	ProviderOptions *map[string]any
	Description     *string
	Auth            *domain.TargetAuth
	HealthChecks    *domain.HealthChecks
	MCPTarget       *domain.MCPTarget
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=registry_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Registry, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Registry, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !in.GatewayID.IsNil() && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrInvalidGatewayID
	}
	if in.Name != nil {
		existing.Name = *in.Name
	}
	if in.Description != nil {
		existing.Description = *in.Description
	}
	applyLLMTargetUpdate(existing, in)
	applyMCPTargetUpdate(existing, in)
	existing.UpdatedAt = time.Now().UTC()
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	publishBackendCacheInvalidation(ctx, u.publisher, u.logger, existing.GatewayID, existing.ID)
	return existing, nil
}

func applyMCPTargetUpdate(existing *domain.Registry, in UpdateInput) {
	if in.MCPTarget == nil {
		return
	}
	incoming := in.MCPTarget
	if prev := existing.MCPTarget; prev != nil {
		if strings.TrimSpace(incoming.URL) == "" {
			incoming.URL = prev.URL
		}
		if incoming.Transport == "" {
			incoming.Transport = prev.Transport
		}
		if incoming.Headers == nil {
			incoming.Headers = prev.Headers
		}
		if incoming.Auth == nil {
			incoming.Auth = prev.Auth
		}
	}
	incoming.Normalize()
	incoming.ResolveSecretsFrom(existing.MCPTarget)
	existing.MCPTarget = incoming
}

func applyLLMTargetUpdate(existing *domain.Registry, in UpdateInput) {
	if in.Provider == nil && in.ProviderOptions == nil && in.Auth == nil && in.HealthChecks == nil {
		return
	}
	if existing.LLMTarget == nil {
		existing.LLMTarget = &domain.LLMTarget{}
	}
	target := existing.LLMTarget
	if in.Provider != nil {
		target.Provider = *in.Provider
	}
	if in.ProviderOptions != nil {
		target.ProviderOptions = *in.ProviderOptions
	}
	if in.Auth != nil {
		in.Auth.ResolveSecretsFrom(target.Auth)
		target.Auth = in.Auth
	}
	if in.HealthChecks != nil {
		target.HealthChecks = in.HealthChecks
	}
}
