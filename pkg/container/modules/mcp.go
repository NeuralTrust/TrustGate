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
	"log/slog"
	"strings"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
)

func MCP(c *container.Container) error {
	if err := c.Provide(mcpclient.New); err != nil {
		return err
	}
	if err := c.Provide(func(client *mcpclient.Client, logger *slog.Logger) appmcp.Dialer {
		return mcpclient.NewCachedDialer(client, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(conn *database.Connection, cipher vaultdomain.Encrypter) vaultdomain.Repository {
		return vaultrepo.NewRepository(conn, cipher)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, logger *slog.Logger) (sts.TokenSigner, error) {
		env := strings.ToLower(strings.TrimSpace(cfg.AppEnv))
		if cfg.Server.STSSigningKey == "" && (env == "prod" || env == "production") {
			return nil, fmt.Errorf("sts: STS_SIGNING_KEY is required when APP_ENV=%s (ephemeral keys are not shared across replicas)", cfg.AppEnv)
		}
		return infrasts.NewSigner(cfg.Server.STSIssuer, cfg.Server.STSSigningKey, logger)
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
	if err := c.Provide(func(
		store appoauth.ConnectStore,
		vault vaultdomain.Repository,
		consumers appconsumer.DataFinder,
		provider appoauth.ProviderClient,
		registrar appoauth.UpstreamRegistrar,
	) appoauth.ConnectService {
		return appoauth.NewConnectService(store, vault, consumers, provider, registrar)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		exchanger sts.Exchanger,
		vault vaultdomain.Repository,
		connect appoauth.ConnectService,
		provider appoauth.ProviderClient,
	) appmcp.CredentialResolver {
		return appmcp.NewCredentialResolver(exchanger, vault, connect, provider)
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
	if err := c.Provide(mcphttp.NewRPCGateway); err != nil {
		return err
	}
	if err := c.Provide(appmcp.NewRoleScoper); err != nil {
		return err
	}
	return c.Provide(mcphttp.NewHandler)
}
