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
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock/controlplane"
	"github.com/NeuralTrust/TrustGate/pkg/infra/catalog/modelsdev"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	catalogrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/catalog"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"go.uber.org/dig"
)

const catalogSyncTimeout = 60 * time.Second

func Catalog(c *container.Container) error {
	if err := provideCatalogRepository(c); err != nil {
		return err
	}
	return provideCatalogServices(c)
}

func provideCatalogRepository(c *container.Container) error {
	return c.Provide(func(conn *database.Connection, appender outboxrepo.Appender) domain.Repository {
		return catalogrepo.NewRepository(conn, appender)
	})
}

func provideCatalogServices(c *container.Container) error {
	if err := c.Provide(func(cfg *config.Config) *modelsdev.Client {
		return modelsdev.NewClient(cfg.Catalog.ModelsDevBaseURL)
	}); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewService); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewPricingResolver); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewModelListing); err != nil {
		return err
	}
	if err := c.Provide(func(
		repo domain.Repository,
		client *modelsdev.Client,
		logger *slog.Logger,
		sig snapshotSignalParams,
		pricing appcatalog.PricingResolver,
		listing appcatalog.ModelListing,
	) appcatalog.Syncer {
		return appcatalog.NewSyncer(repo, client, logger, sig.Signaler, pricing, listing)
	}); err != nil {
		return err
	}
	if err := c.Provide(cataloghttp.NewListProvidersHandler); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewMCPServerCatalog); err != nil {
		return err
	}
	if err := c.Provide(func() controlplane.Client {
		return controlplane.NewClient()
	}); err != nil {
		return err
	}
	if err := c.Provide(newBedrockModelARNLookup); err != nil {
		return err
	}
	if err := c.Provide(newBedrockModelResolver); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewServerlessFilter); err != nil {
		return err
	}
	if err := c.Provide(newLiveModelSource); err != nil {
		return err
	}
	// One instance serves both roles, so the live listing shares the filter's
	// cache, its singleflight and its timeout budget.
	if err := c.Provide(appcatalog.NewLiveCatalog); err != nil {
		return err
	}
	if err := c.Provide(appcatalog.NewRegistryAvailability); err != nil {
		return err
	}
	if err := c.Provide(cataloghttp.NewListMCPServersHandler); err != nil {
		return err
	}
	return c.Provide(cataloghttp.NewListModelsHandler)
}

// bedrockModelARNLookup adapts the infra control plane client to the port the
// resolver depends on.
type bedrockModelARNLookup struct {
	client controlplane.Client
}

func newBedrockModelARNLookup(client controlplane.Client) appcatalog.BedrockModelARNLookup {
	return &bedrockModelARNLookup{client: client}
}

func (l *bedrockModelARNLookup) ResolveModelARN(ctx context.Context, creds appcatalog.BedrockCredentials, arn string) (string, error) {
	return l.client.ResolveModelARN(ctx, controlplane.Credentials{
		Region: creds.Region, AccessKey: creds.AccessKey, SecretKey: creds.SecretKey,
		SessionToken: creds.SessionToken, UseRole: creds.UseRole, RoleARN: creds.RoleARN,
	}, arn)
}

func newBedrockModelResolver(lookup appcatalog.BedrockModelARNLookup, logger *slog.Logger, cfg *config.Config) appcatalog.BedrockModelResolver {
	native := cfg.BedrockNative
	return appcatalog.NewBedrockModelResolverWithLimits(lookup, logger, appcatalog.BedrockResolverLimits{
		MaxInFlight:    native.ResolverMaxInFlight,
		MaxPerRegistry: native.ResolverMaxPerRegistry,
		MaxEntries:     native.ResolverCacheEntries,
		ResolvedTTL:    native.ResolverResolvedTTL,
		UnresolvedTTL:  native.ResolverUnresolvedTTL,
		LookupTimeout:  native.ResolverControlPlaneTimeout,
	})
}

type liveModelSource struct {
	locator factory.ProviderLocator
}

func newLiveModelSource(locator factory.ProviderLocator) appcatalog.LiveModelSource {
	return &liveModelSource{locator: locator}
}

func (s *liveModelSource) Supports(providerCode string) bool {
	_, err := s.locator.GetModelLister(providerCode)
	return err == nil
}

func (s *liveModelSource) List(
	ctx context.Context,
	providerCode string,
	auth *registrydomain.TargetAuth,
	options map[string]any,
) ([]appcatalog.LiveModel, error) {
	lister, err := s.locator.GetModelLister(providerCode)
	if err != nil {
		return nil, err
	}
	models, err := lister.ListLiveModels(ctx, &providers.Config{
		Options:     options,
		Credentials: providers.CredentialsFromTargetAuth(auth),
	})
	if err != nil {
		return nil, err
	}
	out := make([]appcatalog.LiveModel, 0, len(models))
	for _, model := range models {
		out = append(out, appcatalog.LiveModel{ID: model.ID, DisplayName: model.DisplayName, ProviderModel: model.ProviderModel})
	}
	return out, nil
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
