package modules

import (
	gatewayhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	gatewayrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/gateway"
)

// Gateway wires the Gateway aggregate end-to-end: pgx repository,
// the four application services, and the five admin HTTP handlers.
func Gateway(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return gatewayrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(appgateway.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(appgateway.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(appgateway.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(appgateway.NewFinder); err != nil {
		return err
	}

	if err := c.Provide(func(creator appgateway.Creator, cfg *config.Config) *gatewayhttp.CreateGatewayHandler {
		return gatewayhttp.NewCreateGatewayHandler(creator, cfg.Server.GatewayBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(finder appgateway.Finder, cfg *config.Config) *gatewayhttp.GetGatewayHandler {
		return gatewayhttp.NewGetGatewayHandler(finder, cfg.Server.GatewayBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(finder appgateway.Finder, cfg *config.Config) *gatewayhttp.ListGatewayHandler {
		return gatewayhttp.NewListGatewayHandler(finder, cfg.Server.GatewayBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(updater appgateway.Updater, cfg *config.Config) *gatewayhttp.UpdateGatewayHandler {
		return gatewayhttp.NewUpdateGatewayHandler(updater, cfg.Server.GatewayBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(gatewayhttp.NewDeleteGatewayHandler); err != nil {
		return err
	}
	return nil
}
