package modules

import (
	"context"
	"log/slog"
	"time"

	cataloghttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/catalog"
	appcatalog "github.com/NeuralTrust/AgentGateway/pkg/app/catalog"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/catalog"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/catalog/openrouter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	catalogrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/catalog"
	"go.uber.org/dig"
)

const catalogSyncTimeout = 60 * time.Second

func Catalog(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return catalogrepo.NewRepository(conn)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) *openrouter.Client {
		return openrouter.NewClient(cfg.Catalog.OpenRouterBaseURL, cfg.Catalog.OpenRouterAPIKey)
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
