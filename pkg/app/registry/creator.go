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
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

type CreateInput struct {
	GatewayID   ids.GatewayID
	Name        string
	Type        domain.Type
	Enabled     *bool
	Description string
	LLMTarget   *domain.LLMTarget
	MCPTarget   *domain.MCPTarget
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=registry_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Registry, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
}

func NewCreator(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger, signaler configsyncport.SnapshotSignaler) Creator {
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		logger:      logger,
		signaler:    signaler,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Registry, error) {
	var b *domain.Registry
	var err error
	if in.Type == domain.TypeMCP {
		b, err = domain.NewMCPRegistry(
			in.GatewayID,
			in.Name,
			in.Description,
			in.MCPTarget,
		)
	} else {
		if verr := validateProviderOptions(in.LLMTarget); verr != nil {
			return nil, verr
		}
		b, err = domain.NewLLMRegistry(
			in.GatewayID,
			in.Name,
			in.Description,
			in.LLMTarget,
		)
	}
	if err != nil {
		return nil, err
	}
	if in.Enabled != nil {
		b.Enabled = *in.Enabled
	}
	if err := c.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	c.memoryCache.Set(b.ID.String(), b)
	if c.signaler != nil {
		c.signaler.Signal(ctx)
	}
	return b, nil
}

func validateProviderOptions(target *domain.LLMTarget) error {
	if target == nil {
		return nil
	}
	if err := providers.ValidateProviderOptions(target.Provider, target.ProviderOptions); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrInvalidRegistry, err)
	}
	return nil
}
