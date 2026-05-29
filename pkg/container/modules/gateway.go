package modules

import (
	gatewayhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/gateway"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
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

	if err := c.Provide(gatewayhttp.NewCreateGatewayHandler); err != nil {
		return err
	}
	if err := c.Provide(gatewayhttp.NewGetGatewayHandler); err != nil {
		return err
	}
	if err := c.Provide(gatewayhttp.NewListGatewayHandler); err != nil {
		return err
	}
	if err := c.Provide(gatewayhttp.NewUpdateGatewayHandler); err != nil {
		return err
	}
	if err := c.Provide(gatewayhttp.NewDeleteGatewayHandler); err != nil {
		return err
	}
	return nil
}
