package modules

import (
	"log/slog"

	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
	registryhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry"
	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
	mcpsession "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/session"
)

// MCP wires the virtual-MCP composer and its JSON-RPC handler.
func MCP(c *container.Container) error {
	if err := c.Provide(mcpclient.New); err != nil {
		return err
	}
	if err := c.Provide(func(cc cache.Client) appmcp.SessionStore {
		return mcpsession.NewStore(cc.RedisClient())
	}); err != nil {
		return err
	}
	if err := c.Provide(func(client *mcpclient.Client, store appmcp.SessionStore, logger *slog.Logger) appmcp.Dialer {
		return appmcp.NewPinnedDialer(client, store, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(dialer appmcp.Dialer, manager *cache.TTLMapManager, logger *slog.Logger) appmcp.Composer {
		return appmcp.NewComposer(dialer, manager, logger)
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
