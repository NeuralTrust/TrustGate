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

package modules

import (
	"log/slog"

	gatewayhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
)

// Gateway wires the Gateway aggregate end-to-end: pgx repository,
// the four application services, and the five admin HTTP handlers.
func Gateway(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return gatewayrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, exporterFactory appmetrics.ExporterFactory, logger *slog.Logger, sig snapshotSignalParams) appgateway.Creator {
		return appgateway.NewCreator(repo, manager, exporterFactory, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, exporterFactory appmetrics.ExporterFactory, logger *slog.Logger, sig snapshotSignalParams) appgateway.Updater {
		return appgateway.NewUpdater(repo, manager, publisher, exporterFactory, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appgateway.Deleter {
		return appgateway.NewDeleter(repo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(appgateway.NewFinder); err != nil {
		return err
	}

	if err := c.Provide(func(creator appgateway.Creator, cfg *config.Config) *gatewayhttp.CreateGatewayHandler {
		return gatewayhttp.NewCreateGatewayHandler(creator, cfg.Server.GatewayBaseDomain, cfg.Server.MCPBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(finder appgateway.Finder, cfg *config.Config) *gatewayhttp.GetGatewayHandler {
		return gatewayhttp.NewGetGatewayHandler(finder, cfg.Server.GatewayBaseDomain, cfg.Server.MCPBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(finder appgateway.Finder, cfg *config.Config) *gatewayhttp.ListGatewayHandler {
		return gatewayhttp.NewListGatewayHandler(finder, cfg.Server.GatewayBaseDomain, cfg.Server.MCPBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(updater appgateway.Updater, cfg *config.Config) *gatewayhttp.UpdateGatewayHandler {
		return gatewayhttp.NewUpdateGatewayHandler(updater, cfg.Server.GatewayBaseDomain, cfg.Server.MCPBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(gatewayhttp.NewDeleteGatewayHandler); err != nil {
		return err
	}
	return nil
}
