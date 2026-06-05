package modules

import (
	registryhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry"
	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	registryrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/registry"
)

func Registry(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return registryrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(appregistry.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewConnectionTester); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewCreateRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewGetRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewListRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewUpdateRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewDeleteRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewTestConnectionHandler); err != nil {
		return err
	}
	return nil
}
