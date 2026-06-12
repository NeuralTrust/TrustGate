package modules

import (
	rolehttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/role"
	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	rolerepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/role"
)

func Role(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return rolerepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(approle.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(approle.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(approle.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(approle.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(approle.NewAssociator); err != nil {
		return err
	}
	if err := c.Provide(approle.NewIDPResolver); err != nil {
		return err
	}

	if err := c.Provide(rolehttp.NewCreateRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewGetRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewListRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewUpdateRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewDeleteRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewAssociationHandler); err != nil {
		return err
	}
	return nil
}
