package policy

import (
	"errors"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

func validatePlugin(reg appplugins.Registry, slug string, stages []domain.Stage, settings map[string]any) error {
	if err := reg.ValidateStages(slug, stages); err != nil {
		return errors.Join(commonerrors.ErrValidation, err)
	}
	if err := reg.Validate(slug, settings); err != nil {
		return errors.Join(commonerrors.ErrValidation, err)
	}
	return nil
}
