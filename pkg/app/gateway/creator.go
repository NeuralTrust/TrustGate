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

package gateway

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type CreateInput struct {
	Slug            string
	Domain          string
	Metadata        map[string]string
	Telemetry       *telemetry.Telemetry
	ClientTLSConfig domain.ClientTLSConfig
	SessionConfig   *domain.SessionConfig
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=gateway_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Gateway, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo            domain.Repository
	memoryCache     *cache.TTLMap
	exporterFactory appmetrics.ExporterFactory
	logger          *slog.Logger
	signaler        configsyncport.SnapshotSignaler
}

func NewCreator(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	exporterFactory appmetrics.ExporterFactory,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
) Creator {
	return &creator{
		repo:            repo,
		memoryCache:     manager.GetTTLMap(cache.GatewayTTLName),
		exporterFactory: exporterFactory,
		logger:          logger,
		signaler:        signaler,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Gateway, error) {
	if err := validateExporters(c.exporterFactory, in.Telemetry); err != nil {
		return nil, err
	}
	g, err := domain.New(in.Slug)
	if err != nil {
		return nil, err
	}
	g.Domain = in.Domain
	g.Metadata = domain.SanitizeClientMetadata(in.Metadata)
	g.Telemetry = in.Telemetry
	g.ClientTLSConfig = in.ClientTLSConfig
	g.SessionConfig = in.SessionConfig
	if g.SessionConfig == nil {
		g.SessionConfig = domain.DefaultSessionConfig()
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	if err := c.repo.Save(ctx, g); err != nil {
		return nil, err
	}
	setGatewayCache(c.memoryCache, g)
	if c.signaler != nil {
		c.signaler.Signal(ctx)
	}
	return g, nil
}
