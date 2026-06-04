package modules

import (
	authhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/auth"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	authrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/auth"
)

func Auth(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return authrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(appauth.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewAPIKeyFinder); err != nil {
		return err
	}

	if err := c.Provide(authhttp.NewCreateAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewGetAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewListAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewUpdateAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewDeleteAuthHandler); err != nil {
		return err
	}
	return nil
}
