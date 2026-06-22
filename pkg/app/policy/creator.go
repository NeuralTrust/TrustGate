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

package policy

import (
	"context"
	"log/slog"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type CreateInput struct {
	GatewayID   ids.GatewayID
	Name        string
	Description string
	Slug        string
	Enabled     bool
	Priority    int
	Parallel    bool
	Settings    map[string]any
	Stages      []domain.Stage
	Mode        domain.Mode
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=policy_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Policy, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	registry    appplugins.Registry
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewCreator(
	repo domain.Repository,
	registry appplugins.Registry,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
) Creator {
	return &creator{
		repo:        repo,
		registry:    registry,
		memoryCache: manager.GetTTLMap(cache.PolicyTTLName),
		logger:      logger,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Policy, error) {
	p, err := domain.NewPolicy(in.GatewayID, in.Name, in.Slug, in.Enabled, in.Priority, in.Parallel, in.Settings, in.Stages, in.Description, in.Mode)
	if err != nil {
		return nil, err
	}
	if err := validatePlugin(c.registry, in.Slug, in.Stages, in.Settings); err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, p); err != nil {
		return nil, err
	}
	c.memoryCache.Set(p.ID.String(), p)
	return p, nil
}
