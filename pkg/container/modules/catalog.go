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
	"context"
	"log/slog"
	"time"

	cataloghttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/catalog"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/catalog/modelsdev"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	catalogrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/catalog"
	"go.uber.org/dig"
)

const catalogSyncTimeout = 60 * time.Second

func Catalog(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return catalogrepo.NewRepository(conn)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) *modelsdev.Client {
		return modelsdev.NewClient(cfg.Catalog.ModelsDevBaseURL)
	}); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewService); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewSyncer); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewPricingResolver); err != nil {
		return err
	}
	if err := c.Provide(cataloghttp.NewListProvidersHandler); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewMCPServerCatalog); err != nil {
		return err
	}
	if err := c.Provide(cataloghttp.NewListMCPServersHandler); err != nil {
		return err
	}
	return c.Provide(cataloghttp.NewListModelsHandler)
}

type CatalogSyncParams struct {
	dig.In
	Logger *slog.Logger
	Syncer appcatalog.Syncer
}

func StartCatalogSync(p CatalogSyncParams) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), catalogSyncTimeout)
		defer cancel()
		if err := p.Syncer.Sync(ctx); err != nil {
			p.Logger.Warn("catalog sync failed, continuing without refreshed catalog",
				slog.String("error", err.Error()))
		}
	}()
}
