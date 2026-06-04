package modules

import (
	policyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	policyrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/policy"
)

// Policy wires the Policy aggregate end-to-end: pgx repository, the four
// application services, and the five admin HTTP handlers.
func Policy(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return policyrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(apppolicy.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewScoper); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewDuplicator); err != nil {
		return err
	}

	if err := c.Provide(policyhttp.NewCreatePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewGetPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewListPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewUpdatePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewDeletePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewGlobalPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewDuplicatePolicyHandler); err != nil {
		return err
	}
	return nil
}
