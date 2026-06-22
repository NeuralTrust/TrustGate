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
	"time"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type UpdateInput struct {
	ID              ids.GatewayID
	Name            *string
	Slug            *string
	Status          *string
	Domain          *string
	Metadata        map[string]string
	Telemetry       *telemetry.Telemetry
	ClientTLSConfig *domain.ClientTLSConfig
	SessionConfig   *domain.SessionConfig
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=gateway_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Gateway, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo            domain.Repository
	memoryCache     *cache.TTLMap
	publisher       cache.EventPublisher
	exporterFactory appmetrics.ExporterFactory
	logger          *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	exporterFactory appmetrics.ExporterFactory,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:            repo,
		memoryCache:     manager.GetTTLMap(cache.GatewayTTLName),
		publisher:       publisher,
		exporterFactory: exporterFactory,
		logger:          logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Gateway, error) {
	if err := validateExporters(u.exporterFactory, in.Telemetry); err != nil {
		return nil, err
	}
	g, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	old := *g
	if in.Name != nil {
		g.Name = *in.Name
	}
	if in.Slug != nil {
		g.Slug = *in.Slug
	}
	if in.Status != nil {
		g.Status = *in.Status
	}
	if in.Domain != nil {
		g.Domain = *in.Domain
	}
	if in.Metadata != nil {
		g.Metadata = in.Metadata
	}
	if in.Telemetry != nil {
		g.Telemetry = in.Telemetry
	}
	if in.ClientTLSConfig != nil {
		g.ClientTLSConfig = *in.ClientTLSConfig
	}
	if in.SessionConfig != nil {
		g.SessionConfig = in.SessionConfig
	}
	g.UpdatedAt = time.Now().UTC()
	if err := g.Validate(); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, g); err != nil {
		return nil, err
	}
	deleteGatewayCache(u.memoryCache, &old)
	setGatewayCache(u.memoryCache, g)
	publishGatewayDataInvalidation(ctx, u.publisher, u.logger, g.ID)
	return g, nil
}
