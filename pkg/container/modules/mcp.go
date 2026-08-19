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
	"fmt"
	"log/slog"
	"strings"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/ratelimit"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
)

const mcpAppsPipelineReady = false

func MCP(c *container.Container) error {
	if err := c.Provide(mcpclient.New); err != nil {
		return err
	}
	if err := c.Provide(func(client *mcpclient.Client, logger *slog.Logger, cfg *config.Config) appmcp.Dialer {
		return mcpclient.NewNegotiatingDialer(client, logger, mcpclient.NewProtocolDecisionRecorder(cfg.Telemetry.OpsMetricsEnabled))
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, cc cache.Client, logger *slog.Logger) (sts.TokenSigner, error) {
		keyPEM := cfg.Server.STSSigningKey
		if keyPEM == "" {
			env := strings.ToLower(strings.TrimSpace(cfg.AppEnv))
			if env == "prod" || env == "production" {
				resolved, err := infrasts.ResolveSharedSigningKey(context.Background(), cc.RedisClient(), logger)
				if err != nil {
					return nil, err
				}
				keyPEM = resolved
			}
		}
		return infrasts.NewSigner(cfg.Server.STSIssuer, keyPEM, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func() sts.IdPTokenClient {
		return infrasts.NewTokenClient(nil)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(signer sts.TokenSigner, credentials appauth.CredentialFinder, idp sts.IdPTokenClient) sts.Exchanger {
		return sts.NewExchanger(signer, credentials, idp)
	}); err != nil {
		return err
	}
	if err := c.Provide(func() appoauth.ProviderClient {
		return infraoauth.NewProviderClient(nil)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cc cache.Client) *infraoauth.ConnectStore {
		return infraoauth.NewConnectStore(cc.RedisClient())
	}); err != nil {
		return err
	}
	if err := c.Provide(func(s *infraoauth.ConnectStore) appoauth.ConnectStore { return s }); err != nil {
		return err
	}
	if err := c.Provide(func(s *infraoauth.ConnectStore) appoauth.ClientStore { return s }); err != nil {
		return err
	}
	if err := c.Provide(func(clients appoauth.ClientStore) appoauth.UpstreamRegistrar {
		return infraoauth.NewUpstreamRegistrar(clients, nil)
	}); err != nil {
		return err
	}
	if err := c.Provide(provideConnectAttemptLimiter); err != nil {
		return err
	}
	if err := c.Provide(appoauth.NewConnectAuditor); err != nil {
		return err
	}
	if err := c.Provide(func(
		store appoauth.ConnectStore,
		vault vaultdomain.Repository,
		consumers appconsumer.DataFinder,
		provider appoauth.ProviderClient,
		registrar appoauth.UpstreamRegistrar,
		auditor appoauth.ConnectAuditor,
	) appoauth.ConnectService {
		return appoauth.NewConnectService(store, vault, consumers, provider, registrar, auditor)
	}); err != nil {
		return err
	}
	if err := c.Provide(provideAPIKeyConnectService); err != nil {
		return err
	}
	if err := c.Provide(func(
		exchanger sts.Exchanger,
		vault vaultdomain.Repository,
		connect appoauth.ConnectService,
		provider appoauth.ProviderClient,
		logger *slog.Logger,
	) appmcp.CredentialResolver {
		return appmcp.NewCredentialResolver(exchanger, vault, connect, provider, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(manager *cache.TTLMapManager) appmcp.AppCapabilityResolver {
		return mcpclient.NewAppCapabilityResolver(manager.GetTTLMap(cache.MCPAppsTTLName))
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		cfg *config.Config,
		creds appmcp.CredentialResolver,
		resolver appmcp.AppCapabilityResolver,
	) appmcp.AppsMediator {
		return appmcp.NewAppsMediator(cfg.Server.MCPApps.Enabled, mcpAppsPipelineReady, creds, resolver)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) *appmcp.TicketSigner {
		mrtr := cfg.Server.MCPMRTR
		return appmcp.NewTicketSigner(mrtr.TicketSecret, mrtr.TicketSecretPrev, mrtr.TicketTTL, mrtr.MaxRounds)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) *appmcp.TaskHandleSigner {
		tasks := cfg.Server.MCPTasks
		return appmcp.NewTaskHandleSigner(
			tasks.HandleSecret,
			tasks.HandleSecretPrev,
			tasks.HandleTTL,
			tasks.HandleMaxBytes,
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		dialer appmcp.Dialer,
		creds appmcp.CredentialResolver,
		manager *cache.TTLMapManager,
		logger *slog.Logger,
		signer *appmcp.TicketSigner,
		tasks *appmcp.TaskHandleSigner,
		cfg *config.Config,
	) appmcp.Composer {
		return appmcp.NewComposerWithMediation(
			dialer,
			creds,
			manager.GetTTLMap(cache.MCPToolsTTLName),
			logger,
			signer,
			tasks,
			int64(cfg.Server.MCPTasks.PollIntervalFloorMs),
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(appmcp.NewIntrospector); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewListRegistryToolsHandler); err != nil {
		return err
	}
	if err := c.Provide(appmcp.NewPluginRunner); err != nil {
		return err
	}
	if err := c.Provide(func(
		composer appmcp.Composer,
		plugins *appmcp.PluginRunner,
		limiter ratelimitapp.Checker,
		cfg *config.Config,
	) *mcphttp.RPCGateway {
		return mcphttp.NewRPCGatewayWithLimits(
			composer,
			plugins,
			limiter,
			cfg.Server.MCPMRTR.MaxContinuationBytes,
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(appmcp.NewRoleScoper); err != nil {
		return err
	}
	if err := c.Provide(provideSubscriptionRegistry); err != nil {
		return err
	}
	if err := c.Provide(provideSubscriptionConnector); err != nil {
		return err
	}
	if err := c.Provide(provideSubscriptionTargetResolver); err != nil {
		return err
	}
	if err := c.Provide(provideSubscriptionPolicy); err != nil {
		return err
	}
	if err := c.Provide(provideSubscriptionMultiplexer); err != nil {
		return err
	}
	return c.Provide(func(
		gw *mcphttp.RPCGateway,
		scoper appmcp.RoleScoper,
		signer *appmcp.TicketSigner,
		tasks *appmcp.TaskHandleSigner,
		registry *appmcp.SubscriptionRegistry,
		policy appmcp.SubscriptionPolicy,
		targets appmcp.SubscriptionTargetResolver,
		multiplexer *appmcp.SubscriptionMultiplexer,
		apps appmcp.AppsMediator,
		cfg *config.Config,
	) *mcphttp.Handler {
		return mcphttp.NewHandlerWithApps(
			gw,
			scoper,
			mcphttp.MRTRSupport{
				Signer:   signer,
				Recorder: mcphttp.NewMRTRRecorder(cfg.Telemetry.OpsMetricsEnabled),
			},
			mcphttp.TasksSupport{
				Signer:   tasks,
				Recorder: mcphttp.NewTasksRecorder(cfg.Telemetry.OpsMetricsEnabled),
			},
			subscriptionsSupport(
				cfg.Server.MCPSubscriptions,
				registry,
				policy,
				targets,
				multiplexer,
				mcphttp.NewSubscriptionsRecorder(cfg.Telemetry.OpsMetricsEnabled),
			),
			apps,
			mcphttp.NewProtocolValidationRecorder(cfg.Telemetry.OpsMetricsEnabled),
		)
	})
}

// provideSubscriptionRegistry builds the lease accountant, or nil while the
// feature is disabled. A nil registry makes SubscriptionsSupport.Enabled false,
// so the default build behaves exactly as it did before subscriptions existed.
func provideSubscriptionRegistry(cfg *config.Config) *appmcp.SubscriptionRegistry {
	subs := cfg.Server.MCPSubscriptions
	if !subs.Enabled {
		return nil
	}
	return appmcp.NewSubscriptionRegistry(appmcp.SubscriptionCaps{
		MaxStreams:      subs.MaxStreams,
		MaxPerConsumer:  subs.MaxPerConsumer,
		MaxPerPrincipal: subs.MaxPerPrincipal,
	})
}

// provideSubscriptionPolicy builds the re-authorization pass, or a nil interface
// while the feature is disabled. The nil must be a literal rather than a typed
// nil pointer, since SubscriptionsSupport.Enabled compares the interface itself.
func provideSubscriptionPolicy(
	cfg *config.Config,
	consumers appconsumer.DataFinder,
	scoper appmcp.RoleScoper,
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	creds appmcp.CredentialResolver,
	connector appmcp.SubscriptionConnector,
) appmcp.SubscriptionPolicy {
	if !cfg.Server.MCPSubscriptions.Enabled {
		return nil
	}
	if cfg.Server.MCPSubscriptions.UpstreamEnabled {
		return appmcp.NewSubscriptionPolicyWithUpstream(
			consumers,
			scoper,
			composer,
			plugins,
			creds,
			connector,
		)
	}
	return appmcp.NewSubscriptionPolicy(consumers, scoper, composer, plugins)
}

func provideSubscriptionConnector(cfg *config.Config) appmcp.SubscriptionConnector {
	subs := cfg.Server.MCPSubscriptions
	if !subs.Enabled || !subs.UpstreamEnabled {
		return nil
	}
	return mcpclient.NewModernSubscriptionConnector(subs.MaxEventBytes, subs.UpstreamIdleTimeout)
}

func provideSubscriptionTargetResolver(
	cfg *config.Config,
	consumers appconsumer.DataFinder,
	scoper appmcp.RoleScoper,
	creds appmcp.CredentialResolver,
) appmcp.SubscriptionTargetResolver {
	subs := cfg.Server.MCPSubscriptions
	if !subs.Enabled || !subs.UpstreamEnabled {
		return nil
	}
	return appmcp.NewSubscriptionTargetResolver(consumers, scoper, creds)
}

func provideSubscriptionMultiplexer(
	cfg *config.Config,
	policy appmcp.SubscriptionPolicy,
	connector appmcp.SubscriptionConnector,
	targets appmcp.SubscriptionTargetResolver,
) (*appmcp.SubscriptionMultiplexer, error) {
	subs := cfg.Server.MCPSubscriptions
	if !subs.Enabled || !subs.UpstreamEnabled {
		return nil, nil
	}
	upstreamPolicy, ok := policy.(appmcp.UpstreamSubscriptionPolicy)
	if !ok {
		return nil, fmt.Errorf("mcp: upstream subscription policy is unavailable")
	}
	refresher, ok := targets.(appmcp.SubscriptionTargetRefresher)
	if !ok {
		return nil, fmt.Errorf("mcp: upstream subscription target refresher is unavailable")
	}
	return appmcp.NewSubscriptionMultiplexer(
		context.Background(),
		connector,
		upstreamPolicy.AuthorizeEvent,
		appmcp.SubscriptionMultiplexerOptions{
			MaxListeners:         subs.MaxUpstreamListeners,
			MaxPerOrigin:         subs.MaxUpstreamPerOrigin,
			QueueCapacity:        subs.StreamQueue,
			ReconnectAttempts:    subs.ReconnectMaxAttempts,
			ReconnectBackoffMin:  subs.ReconnectBackoffMin,
			ReconnectBackoffMax:  subs.ReconnectBackoffMax,
			AuthorizationTimeout: appmcp.ReauthBudget(subs.ReauthInterval, subs.Keepalive),
			Refresher:            refresher,
			Recorder: mcphttp.NewSubscriptionSourceRecorder(
				cfg.Telemetry.OpsMetricsEnabled,
			),
		},
	)
}

// subscriptionsSupport carries the configured bounds to the handler. Nothing is
// constructed while the feature is disabled: the value is inert and the default
// build behaves exactly as it did before subscriptions existed.
func subscriptionsSupport(
	cfg config.MCPSubscriptionsConfig,
	registry *appmcp.SubscriptionRegistry,
	policy appmcp.SubscriptionPolicy,
	targets appmcp.SubscriptionTargetResolver,
	multiplexer *appmcp.SubscriptionMultiplexer,
	recorder mcphttp.SubscriptionsRecorder,
) mcphttp.SubscriptionsSupport {
	var source appmcp.SubscriptionSource
	if multiplexer != nil {
		source = multiplexer
	}
	return mcphttp.SubscriptionsSupport{
		On:             cfg.Enabled,
		MaxLifetime:    cfg.MaxLifetime,
		ReauthInterval: cfg.ReauthInterval,
		Keepalive:      cfg.Keepalive,
		MaxEventBytes:  cfg.MaxEventBytes,
		MaxURIs:        cfg.MaxURIs,
		Registry:       registry,
		Policy:         policy,
		Recorder:       recorder,
		Upstream:       cfg.UpstreamEnabled,
		Targets:        targets,
		Source:         source,
	}
}

func provideAPIKeyConnectService(
	apiKeys appauth.APIKeyFinder,
	consumers appconsumer.DataFinder,
	connect appoauth.ConnectService,
	limiter appoauth.ConnectAttemptLimiter,
) appoauth.APIKeyConnectService {
	return appoauth.NewAPIKeyConnectService(apiKeys, consumers, connect, limiter)
}

func provideConnectAttemptLimiter(
	cfg *config.Config,
	cc cache.Client,
	_ vaultdomain.Encrypter,
) appoauth.ConnectAttemptLimiter {
	if !cfg.MCPConnectRateLimit.Enabled {
		return appoauth.NewNoopConnectAttemptLimiter()
	}
	return ratelimit.NewConnectAttemptLimiter(
		cc.RedisClient(),
		cfg.Server.SecretKey,
		cfg.MCPConnectRateLimit,
	)
}

func MCPVaultPostgres(c *container.Container) error {
	return c.Provide(func(conn *database.Connection, cipher vaultdomain.Encrypter) vaultdomain.Repository {
		return vaultrepo.NewRepository(conn, cipher)
	})
}

func MCPVaultRedis(c *container.Container) error {
	return c.Provide(func(cc cache.Client, cipher vaultdomain.Encrypter, logger *slog.Logger) vaultdomain.Repository {
		vaultrepo.WarnIfVolatile(context.Background(), cc.RedisClient(), logger)
		return vaultrepo.NewRedisRepository(cc.RedisClient(), cipher)
	})
}
