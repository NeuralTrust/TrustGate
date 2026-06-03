package registry

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrNotFound               = fmt.Errorf("registry: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists          = fmt.Errorf("registry: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents          = fmt.Errorf("registry: %w", commonerrors.ErrHasDependents)
	ErrInvalidGatewayID       = fmt.Errorf("registry: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidRegistryID      = fmt.Errorf("registry: invalid registry_id: %w", commonerrors.ErrValidation)
	ErrInvalidEmbeddingConfig = fmt.Errorf("registry: invalid embedding config: %w", commonerrors.ErrValidation)
	ErrInvalidRegistry        = fmt.Errorf("registry: invalid backend: %w", commonerrors.ErrValidation)
	ErrInvalidHealthChecks    = fmt.Errorf("registry: invalid health checks: %w", commonerrors.ErrValidation)
)
