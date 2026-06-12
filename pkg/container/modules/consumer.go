package modules

import (
	consumerhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	consumerrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/consumer"
)

func Consumer(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return consumerrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(appconsumer.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewDataFinder); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewPathResolver); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewAssociator); err != nil {
		return err
	}

	if err := c.Provide(consumerhttp.NewCreateConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewGetConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewListConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewUpdateConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewDeleteConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewAssociationHandler); err != nil {
		return err
	}
	return nil
}
