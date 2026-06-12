package modules

import (
	"fmt"
	"log/slog"

	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
	registryhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	vaultdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/crypto"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	infrasts "github.com/NeuralTrust/AgentGateway/pkg/infra/identity/sts"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
	infraoauth "github.com/NeuralTrust/AgentGateway/pkg/infra/oauth"
	vaultrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/vault"
)

// MCP wires the virtual-MCP composer, the Phase 4 downstream-credential
// machinery (STS, vault, OAuth broker), and the JSON-RPC handler.
func MCP(c *container.Container) error {
	if err := c.Provide(mcpclient.New); err != nil {
		return err
	}
	if err := c.Provide(func(client *mcpclient.Client, logger *slog.Logger) appmcp.Dialer {
		return mcpclient.NewCachedDialer(client, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) (vaultdomain.Encrypter, error) {
		return crypto.NewCipher(cfg.Server.SecretKey)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(conn *database.Connection, cipher vaultdomain.Encrypter) vaultdomain.Repository {
		return vaultrepo.NewRepository(conn, cipher)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, logger *slog.Logger) (sts.TokenSigner, error) {
		// An ephemeral per-replica key in prod breaks JWKS verification across
		// replicas (each one would publish a different key), so refuse to boot.
		if cfg.Server.STSSigningKey == "" && cfg.AppEnv == "prod" {
			return nil, fmt.Errorf("sts: STS_SIGNING_KEY is required when APP_ENV=prod (ephemeral keys are not shared across replicas)")
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
	if err := c.Provide(appmcp.NewRPCGateway); err != nil {
		return err
	}
	return c.Provide(mcphttp.NewHandler)
}
