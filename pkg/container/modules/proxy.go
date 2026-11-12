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
	"fmt"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"log/slog"

	proxyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/proxy"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	appsession "github.com/NeuralTrust/TrustGate/pkg/app/session"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/console"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/tokenratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"go.uber.org/dig"
)

func Proxy(c *container.Container) error {
	if err := c.Provide(approuting.NewResolver); err != nil {
		return err
	}
	// NewProviderInvoker depends on a segregated codec view; the concrete adapter
	// registry satisfies it, but dig resolves by exact type so we bind it here.
	if err := c.Provide(func(
		locator factory.ProviderLocator,
		registry *adapter.Registry,
		logger *slog.Logger,
		catalog catalogdomain.Repository,
		models appcatalog.BedrockModelResolver,
		cfg *config.Config,
	) appproxy.ProviderInvoker {
		return appproxy.NewProviderInvoker(locator, registry, logger,
			appproxy.WithCatalog(catalog), appproxy.WithBedrockModelResolver(models),
			appproxy.WithNativeMaxResponseBytes(cfg.BedrockNative.MaxResponseBytes))
	}); err != nil {
		return err
	}
	// The forwarder's load balancer only needs the Redis accessor; expose the
	// cache client under that narrow view (dig resolves by exact type).
	if err := c.Provide(func(client cache.Client) loadbalancer.RedisProvider { return client }); err != nil {
		return err
	}
	if err := c.Provide(newGroupBudget); err != nil {
		return err
	}
	// The stream guard needs the same adapter registry under its own narrow
	// view; dig resolves by exact type, so bind it here as the invoker does.
	if err := c.Provide(func(
		factory loadbalancer.Factory,
		cacheClient loadbalancer.RedisProvider,
		manager *cache.TTLMapManager,
		invoker appproxy.ProviderInvoker,
		executor appplugins.Executor,
		sessions appsession.Store,
		resolver approuting.Resolver,
		listing appcatalog.ModelListing,
		limiter ratelimitapp.Checker,
		registry *adapter.Registry,
		bedrockModels appcatalog.BedrockModelResolver,
		groupBudget *tokenratelimit.GroupBudget,
		usage forwarderUsage,
		secrets forwarderSecrets,
		cfg *config.Config,
		logger *slog.Logger,
	) appproxy.Forwarder {
		opts := []appproxy.ForwarderOption{
			appproxy.WithStreamCodec(registry),
			appproxy.WithForwarderBedrockModelResolver(bedrockModels),
			appproxy.WithGroupBudget(groupBudget),
		}
		if secrets.Refresher != nil {
			opts = append(opts, appproxy.WithSecretRefresher(secrets.Refresher))
		}
		if usage.Guard != nil {
			opts = append(opts, appproxy.WithManagedLimit(usage.Guard))
		}
		return appproxy.NewForwarder(
			factory, cacheClient, manager, invoker, executor, sessions, resolver, listing, limiter, cfg, logger,
			opts...,
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewModelsLister); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewStoreSelector); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewStoreModels); err != nil {
		return err
	}
	return c.Provide(func(
		fwd appproxy.Forwarder,
		models appproxy.ModelsLister,
		selector appproxy.StoreSelector,
		storeModels appproxy.StoreModels,
		cfg *config.Config,
		logger *slog.Logger,
	) *proxyhttp.ForwardedHandler {
		return proxyhttp.NewForwardedHandler(fwd).
			WithModels(models).
			WithStore(selector, storeModels).
			WithClientIPResolver(requestmeta.NewIPResolver(cfg.ClientIP.Mode, cfg.ClientIP.TrustedProxyCIDRs)).
			WithLogger(logger)
	})
}

// forwarderUsage is the usage guard the forwarder skips managed registries
// with; planes without one enforce no usage.
type forwarderUsage struct {
	dig.In
	Guard *middleware.UsageGuardMiddleware `optional:"true"`
}

// newGroupBudget is the stage that holds a group key's store requests to its
// group's budget, on the token_rate_limiter's counters and pricing. When
// CONSOLE_EVENTS_URL is set on this plane it tells the console the first time
// a limit is reached in a month; without it limits are enforced and nobody is
// told.
func newGroupBudget(
	cfg *config.Config,
	cacheClient cache.Client,
	registry *adapter.Registry,
	pricing appcatalog.PricingResolver,
	gateways gatewaydomain.Repository,
	logger *slog.Logger,
) (*tokenratelimit.GroupBudget, error) {
	var notifier keygroupdomain.Notifier
	if endpoint := cfg.Server.ConsoleEventsURL; endpoint != "" {
		events, err := console.NewKeyGroupBudgetEvents(endpoint, cfg.Server.SecretKey, gateways, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", commonerrors.ErrInvalidConfig, err)
		}
		notifier = events
	}
	return tokenratelimit.NewGroupBudget(cacheClient.RedisClient(), registry, pricing, notifier, logger), nil
}

// forwarderSecrets is the refresher the forwarder retries a rejected
// referenced credential with; absent on a plane without the secret stores
// module.
type forwarderSecrets struct {
	dig.In
	Refresher appsecretref.Materializer `optional:"true"`
}
