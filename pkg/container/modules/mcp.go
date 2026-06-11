package modules

import (
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
		return appmcp.NewCachedDialer(client, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) (*crypto.Cipher, error) {
		return crypto.NewCipher(cfg.Server.SecretKey)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(conn *database.Connection, cipher *crypto.Cipher) vaultdomain.Repository {
		return vaultrepo.NewRepository(conn, cipher)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, logger *slog.Logger) (*sts.Signer, error) {
		return sts.NewSigner(cfg.Server.STSIssuer, cfg.Server.STSSigningKey, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(signer *sts.Signer, credentials appauth.CredentialFinder) sts.Exchanger {
		return sts.NewExchanger(signer, credentials, nil)
	}); err != nil {
		return err
	}
	if err := c.Provide(func() *appoauth.ProviderClient {
		return appoauth.NewProviderClient(nil)
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
	if err := c.Provide(func(clients appoauth.ClientStore) *appoauth.UpstreamRegistrar {
		return appoauth.NewUpstreamRegistrar(clients, nil)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		store appoauth.ConnectStore,
		vault vaultdomain.Repository,
		consumers appconsumer.DataFinder,
		provider *appoauth.ProviderClient,
		registrar *appoauth.UpstreamRegistrar,
	) appoauth.ConnectService {
		return appoauth.NewConnectService(store, vault, consumers, provider, registrar)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		exchanger sts.Exchanger,
		vault vaultdomain.Repository,
		connect appoauth.ConnectService,
		provider *appoauth.ProviderClient,
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
		return appmcp.NewComposer(dialer, creds, manager, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(appmcp.NewIntrospector); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewListRegistryToolsHandler); err != nil {
		return err
	}
	return c.Provide(mcphttp.NewHandler)
}
