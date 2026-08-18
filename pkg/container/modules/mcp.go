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
	if err := c.Provide(func(cfg *config.Config) *appmcp.TicketSigner {
		mrtr := cfg.Server.MCPMRTR
		return appmcp.NewTicketSigner(mrtr.TicketSecret, mrtr.TicketSecretPrev, mrtr.TicketTTL, mrtr.MaxRounds)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		dialer appmcp.Dialer,
		creds appmcp.CredentialResolver,
		manager *cache.TTLMapManager,
		logger *slog.Logger,
		signer *appmcp.TicketSigner,
	) appmcp.Composer {
		return appmcp.NewComposerWithSigner(
			dialer,
			creds,
			manager.GetTTLMap(cache.MCPToolsTTLName),
			logger,
			signer,
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
	return c.Provide(func(
		gw *mcphttp.RPCGateway,
		scoper appmcp.RoleScoper,
		signer *appmcp.TicketSigner,
		cfg *config.Config,
	) *mcphttp.Handler {
		return mcphttp.NewHandlerWithMRTR(
			gw,
			scoper,
			mcphttp.MRTRSupport{
				Signer:   signer,
				Recorder: mcphttp.NewMRTRRecorder(cfg.Telemetry.OpsMetricsEnabled),
			},
			mcphttp.NewProtocolValidationRecorder(cfg.Telemetry.OpsMetricsEnabled),
		)
	})
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
