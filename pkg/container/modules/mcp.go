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
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
	mcpopenapi "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/openapi"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/ratelimit"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
	"go.uber.org/dig"
)

const mcpAppsPipelineReady = true

func MCP(c *container.Container) error {
	if err := c.Provide(mcpclient.New); err != nil {
		return err
	}
	if err := c.Provide(func(
		client *mcpclient.Client,
		logger *slog.Logger,
		cfg *config.Config,
		compiler appopenapi.Compiler,
	) appmcp.Dialer {
		remote := mcpclient.NewNegotiatingDialer(
			client,
			logger,
			mcpclient.NewProtocolDecisionRecorder(cfg.Telemetry.OpsMetricsEnabled),
		)
		return mcpopenapi.NewDialer(remote, compiler)
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
	if err := c.Provide(provideConnectService); err != nil {
		return err
	}
	if err := c.Provide(provideConfigureService); err != nil {
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
	if err := c.Provide(provideAppsMetadataPolicy); err != nil {
		return err
	}
	if err := c.Provide(provideAppsListPolicy); err != nil {
		return err
	}
	if err := c.Provide(provideAppsReadPolicy); err != nil {
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
	if err := c.Provide(provideComposer); err != nil {
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
	if err := c.Provide(func(connect appoauth.ConnectService) appmcp.ConnectionGateway {
		return connect
	}); err != nil {
		return err
	}
	if err := c.Provide(appmcp.NewConnectionTool); err != nil {
		return err
	}
	if err := c.Provide(provideRPCGateway); err != nil {
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
	return c.Provide(provideMCPHandler)
}

// mcpHandlerParams wires the MCP HTTP handler. Installs is optional: when present
// the notification stream also watches the caller's Store installations, so a
// self-service install pushes tools/list_changed like connecting an account does.
type mcpHandlerParams struct {
	dig.In

	Gateway     *mcphttp.RPCGateway
	RoleScoper  appmcp.RoleScoper
	Vault       vaultdomain.Repository
	Signer      *appmcp.TicketSigner
	Tasks       *appmcp.TaskHandleSigner
	Registry    *appmcp.SubscriptionRegistry
	Policy      appmcp.SubscriptionPolicy
	Targets     appmcp.SubscriptionTargetResolver
	Multiplexer *appmcp.SubscriptionMultiplexer
	Apps        appmcp.AppsMediator
	Config      *config.Config
	Installs    installationdomain.Repository `optional:"true"`
}

func provideMCPHandler(p mcpHandlerParams) *mcphttp.Handler {
	metrics := p.Config.Telemetry.OpsMetricsEnabled
	opts := []mcphttp.HandlerOption{
		mcphttp.WithProtocolRecorder(mcphttp.NewProtocolValidationRecorder(metrics)),
		mcphttp.WithMRTR(mcphttp.MRTRSupport{
			Signer:   p.Signer,
			Recorder: mcphttp.NewMRTRRecorder(metrics),
		}),
		mcphttp.WithTasks(mcphttp.TasksSupport{
			Signer:   p.Tasks,
			Recorder: mcphttp.NewTasksRecorder(metrics),
		}),
		mcphttp.WithSubscriptions(subscriptionsSupport(
			p.Config.Server.MCPSubscriptions,
			p.Registry,
			p.Policy,
			p.Targets,
			p.Multiplexer,
			mcphttp.NewSubscriptionsRecorder(metrics),
		)),
		mcphttp.WithApps(p.Apps),
	}
	if p.Installs != nil {
		opts = append(opts, mcphttp.WithInstallations(p.Installs))
	}
	return mcphttp.NewHandler(p.Gateway, p.RoleScoper, p.Vault, opts...)
}

// composerParams wires the MCP composer. Installs is optional: present on the
// full plane (Postgres) and the DB-less data plane (gRPC channel), absent on a
// SEARCH-only plane. When present it powers the per-user URL-variable resolver so
// catalog servers whose URL carries placeholders (Snowflake, ServiceNow, …) dial
// each principal's own upstream.
type composerParams struct {
	dig.In

	Dialer   appmcp.Dialer
	Creds    appmcp.CredentialResolver
	Manager  *cache.TTLMapManager
	Logger   *slog.Logger
	Signer   *appmcp.TicketSigner
	Tasks    *appmcp.TaskHandleSigner
	Config   *config.Config
	Installs installationdomain.Repository `optional:"true"`
	Vault    vaultdomain.Repository        `optional:"true"`
}

func provideComposer(p composerParams) appmcp.Composer {
	var opts []appmcp.ComposerOption
	if p.Installs != nil {
		opts = append(opts, appmcp.WithURLValues(appmcp.NewURLValueResolver(p.Installs, p.Vault)))
	}
	return appmcp.NewComposerWithMediation(
		p.Dialer,
		p.Creds,
		p.Manager.GetTTLMap(cache.MCPToolsTTLName),
		p.Logger,
		p.Signer,
		p.Tasks,
		int64(p.Config.Server.MCPTasks.PollIntervalFloorMs),
		opts...,
	)
}

type connectServiceParams struct {
	dig.In

	Store      appoauth.ConnectStore
	Vault      vaultdomain.Repository
	Consumers  appconsumer.DataFinder
	Provider   appoauth.ProviderClient
	Registrar  appoauth.UpstreamRegistrar
	Auditor    appoauth.ConnectAuditor
	Shared     mcpoauth.Provider
	Userinfo   appoauth.UserInfoClient
	Catalog    appcatalog.MCPServerCatalog `optional:"true"`
	Registries registrydomain.Repository   `optional:"true"`
}

type rpcGatewayParams struct {
	dig.In

	Composer    appmcp.Composer
	Plugins     *appmcp.PluginRunner
	Limiter     ratelimitapp.Checker
	Connections appmcp.ConnectionTool
	Shared      mcpoauth.Provider
	AppsList    appmcp.AppsListPolicy
	AppsRead    appmcp.AppsReadPolicy
	Config      *config.Config
	Catalog     appcatalog.MCPServerCatalog `optional:"true"`
	// Install path — present on the full/control plane only. When any is absent
	// the Store offers SEARCH but not INSTALL (e.g. the Redis data plane, which
	// has no installation store yet).
	Registries registrydomain.Repository     `optional:"true"`
	Installs   installationdomain.Repository `optional:"true"`
	// Grants is the Store access model (who may use which catalog server or
	// instance). The full plane reads Postgres, the data plane the snapshot.
	// Absent, nothing is granted under Selected access (fail closed).
	Grants storeaccessdomain.Reader `optional:"true"`
	// Policies are the per-principal access levels the Store mode is resolved
	// from live (own → groups → gateway default). Absent, the legacy token claim
	// / gateway default rule applies.
	Policies storeaccessdomain.PolicyReader `optional:"true"`
	// Ensurer materialises the shared registry on a self-service install. The
	// full plane provides the direct (Creator-backed) implementation; the data
	// plane provides the gRPC-client one. Absent on SEARCH-only planes, where a
	// self-service install downgrades to a pending request.
	Ensurer appstore.RegistryEnsurer `optional:"true"`
	// Configure mints the hosted-form link where a user enters a server's per-user
	// URL variables. Nil on planes without the installation/vault stores; then the
	// install tool reports the needed variables but offers no link.
	Configure appoauth.ConfigureService `optional:"true"`
	// Connect mints the OAuth connect link the install returns for a server that
	// needs the user's own account (the install's second step).
	Connect appoauth.ConnectService `optional:"true"`
}

func provideRPCGateway(p rpcGatewayParams) (*mcphttp.RPCGateway, error) {
	catalog := p.Catalog
	if catalog == nil {
		loaded, err := appcatalog.NewMCPServerCatalog(p.Shared)
		if err != nil {
			return nil, err
		}
		catalog = loaded
	}

	var installer appstore.Installer
	if p.Registries != nil && p.Installs != nil {
		made, err := appstore.NewInstaller(catalog, p.Registries, p.Installs, p.Grants, p.Ensurer)
		if err != nil {
			return nil, err
		}
		installer = made
	}

	var registries appstore.RegistryLister
	if p.Registries != nil {
		registries = p.Registries
	}
	var grants storeaccessdomain.Reader
	if p.Grants != nil {
		grants = p.Grants
	}
	var configure appmcp.ConfigureGateway
	if p.Configure != nil {
		configure = p.Configure
	}
	var connect appmcp.ServerConnectGateway
	if p.Connect != nil {
		connect = p.Connect
	}
	modes := appstore.NewModeResolver(p.Policies)
	store, err := appmcp.NewStoreToolWithInstaller(catalog, installer, registries, grants, configure, connect,
		appmcp.WithStoreToolModes(modes))
	if err != nil {
		return nil, err
	}
	metrics := p.Config.Telemetry.OpsMetricsEnabled
	gateway := mcphttp.NewRPCGatewayWithMetaTools(p.Composer, p.Plugins, p.Limiter, p.Connections, store).
		WithAppsPolicies(p.AppsList, p.AppsRead, mcphttp.NewAppsRecorder(metrics)).
		WithMaxContinuationBytes(p.Config.Server.MCPMRTR.MaxContinuationBytes)

	if p.Installs != nil && p.Registries != nil {
		scoper, err := appstore.NewScoper(p.Installs, p.Registries, grants, appstore.WithScoperModes(modes))
		if err != nil {
			return nil, err
		}
		gateway = gateway.WithStoreScoper(scoper)
	}
	return gateway, nil
}

// configureServiceParams wires the MCP-Store per-user configure flow. Every dep
// is optional so the provider degrades to nil on a plane that lacks the
// installation or vault stores (e.g. a SEARCH-only proxy); the install tool then
// simply offers no configure link.
type configureServiceParams struct {
	dig.In

	Store     appoauth.ConnectStore         `optional:"true"`
	Consumers appconsumer.DataFinder        `optional:"true"`
	Vault     vaultdomain.Repository        `optional:"true"`
	Installs  installationdomain.Repository `optional:"true"`
	Catalog   appcatalog.MCPServerCatalog   `optional:"true"`
	Shared    mcpoauth.Provider
	// Registries, Ensurer and Gateways let a configure-before-install submission
	// run through the same governed installer the install tool uses (shelf,
	// approval, group gates, self-service materialisation). Without Registries the
	// form can only update an existing installation, never create one.
	Registries registrydomain.Repository      `optional:"true"`
	Grants     storeaccessdomain.Reader       `optional:"true"`
	Policies   storeaccessdomain.PolicyReader `optional:"true"`
	Ensurer    appstore.RegistryEnsurer       `optional:"true"`
	Gateways   gatewaydomain.Repository       `optional:"true"`
}

func provideConfigureService(p configureServiceParams) (appoauth.ConfigureService, error) {
	if p.Store == nil || p.Consumers == nil || p.Vault == nil || p.Installs == nil {
		return nil, nil
	}
	catalog := p.Catalog
	if catalog == nil {
		loaded, err := appcatalog.NewMCPServerCatalog(p.Shared)
		if err != nil {
			return nil, err
		}
		catalog = loaded
	}
	var opts []appoauth.ConfigureOption
	if p.Registries != nil {
		installer, err := appstore.NewInstaller(catalog, p.Registries, p.Installs, p.Grants, p.Ensurer)
		if err != nil {
			return nil, err
		}
		opts = append(opts, appoauth.WithConfigureInstaller(installer))
	}
	if p.Gateways != nil {
		// The form-driven first install runs the same live mode decision as the
		// install tool: the principal's policy, else the gateway default.
		gateways := p.Gateways
		modes := appstore.NewModeResolver(p.Policies)
		opts = append(opts, appoauth.WithConfigureOpenMode(func(ctx context.Context, gatewayID ids.GatewayID) bool {
			gw, err := gateways.FindByID(ctx, gatewayID)
			if err != nil || gw == nil {
				return false // unknown gateway: fail closed to curated
			}
			return modes.Mode(appgateway.WithGateway(ctx, gw), gatewayID) == gatewaydomain.StoreModeOpen
		}))
	}
	return appoauth.NewConfigureService(p.Store, p.Consumers, catalog, p.Installs, p.Vault, opts...), nil
}

func provideConnectService(p connectServiceParams) (appoauth.ConnectService, error) {
	catalog := p.Catalog
	if catalog == nil {
		loaded, err := appcatalog.NewMCPServerCatalog(p.Shared)
		if err != nil {
			return nil, err
		}
		catalog = loaded
	}
	var registries appoauth.RegistryLister
	if p.Registries != nil {
		registries = p.Registries
	}
	return appoauth.NewConnectService(
		p.Store,
		p.Vault,
		p.Consumers,
		p.Provider,
		p.Registrar,
		p.Auditor,
		p.Shared,
		p.Userinfo,
		catalog,
		registries,
	), nil
}

func provideAppsMetadataPolicy(cfg *config.Config) (appmcp.AppsMetadataPolicy, error) {
	apps := cfg.Server.MCPApps
	return appmcp.NewAppsMetadataPolicy(
		apps.MaxCSPOriginsPerDirective,
		apps.MaxCSPOriginsTotal,
		apps.AllowedOriginPatterns,
		apps.AllowedPermissions,
	)
}

func provideAppsListPolicy(cfg *config.Config, metadata appmcp.AppsMetadataPolicy) appmcp.AppsListPolicy {
	return appmcp.NewAppsListPolicy(cfg.Server.MCPApps.Enabled && mcpAppsPipelineReady, metadata)
}

func provideAppsReadPolicy(cfg *config.Config, metadata appmcp.AppsMetadataPolicy) appmcp.AppsReadPolicy {
	apps := cfg.Server.MCPApps
	return appmcp.NewAppsReadPolicy(apps.Enabled && mcpAppsPipelineReady, apps.MaxResourceBytes, metadata)
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
	appsListPolicy appmcp.AppsListPolicy,
	creds appmcp.CredentialResolver,
	connector appmcp.SubscriptionConnector,
) appmcp.SubscriptionPolicy {
	if !cfg.Server.MCPSubscriptions.Enabled {
		return nil
	}
	if cfg.Server.MCPSubscriptions.UpstreamEnabled {
		return appmcp.NewSubscriptionPolicyWithUpstreamAndAppsListPolicy(
			consumers,
			scoper,
			composer,
			plugins,
			appsListPolicy,
			creds,
			connector,
		)
	}
	return appmcp.NewSubscriptionPolicyWithAppsListPolicy(
		consumers,
		scoper,
		composer,
		appsListPolicy,
		plugins,
	)
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
