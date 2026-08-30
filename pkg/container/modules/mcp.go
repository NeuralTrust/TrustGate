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
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
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

func MCP(c *container.Container) error {
	if err := c.Provide(mcpclient.New); err != nil {
		return err
	}
	if err := c.Provide(func(client *mcpclient.Client, logger *slog.Logger, compiler appopenapi.Compiler) appmcp.Dialer {
		remote := mcpclient.NewCachedDialer(client, logger)
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
	if err := c.Provide(func(
		dialer appmcp.Dialer,
		creds appmcp.CredentialResolver,
		manager *cache.TTLMapManager,
		logger *slog.Logger,
	) appmcp.Composer {
		return appmcp.NewComposer(dialer, creds, manager.GetTTLMap(cache.MCPToolsTTLName), logger)
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
	return c.Provide(mcphttp.NewHandler)
}

type connectServiceParams struct {
	dig.In

	Store     appoauth.ConnectStore
	Vault     vaultdomain.Repository
	Consumers appconsumer.DataFinder
	Provider  appoauth.ProviderClient
	Registrar appoauth.UpstreamRegistrar
	Auditor   appoauth.ConnectAuditor
	Shared    mcpoauth.Provider
	Userinfo  appoauth.UserInfoClient
	Catalog   appcatalog.MCPServerCatalog `optional:"true"`
}

type rpcGatewayParams struct {
	dig.In

	Composer    appmcp.Composer
	Plugins     *appmcp.PluginRunner
	Limiter     ratelimitapp.Checker
	Connections appmcp.ConnectionTool
	Shared      mcpoauth.Provider
	Catalog     appcatalog.MCPServerCatalog `optional:"true"`
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
	store, err := appmcp.NewStoreTool(catalog)
	if err != nil {
		return nil, err
	}
	return mcphttp.NewRPCGatewayWithMetaTools(p.Composer, p.Plugins, p.Limiter, p.Connections, store), nil
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
	), nil
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
