package modules

import (
	backendhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/backend"
	appbackend "github.com/NeuralTrust/AgentGateway/pkg/app/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	backendrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/backend"
)

func Backend(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return backendrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(appbackend.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(appbackend.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(appbackend.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(appbackend.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appbackend.NewBackendResolver); err != nil {
		return err
	}

	if err := c.Provide(backendhttp.NewCreateBackendHandler); err != nil {
		return err
	}
	if err := c.Provide(backendhttp.NewGetBackendHandler); err != nil {
		return err
	}
	if err := c.Provide(backendhttp.NewListBackendHandler); err != nil {
		return err
	}
	if err := c.Provide(backendhttp.NewUpdateBackendHandler); err != nil {
		return err
	}
	if err := c.Provide(backendhttp.NewDeleteBackendHandler); err != nil {
		return err
	}
	return nil
}
