package backend

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrNotFound               = fmt.Errorf("backend: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists          = fmt.Errorf("backend: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents          = fmt.Errorf("backend: %w", commonerrors.ErrHasDependents)
	ErrInvalidGatewayID       = fmt.Errorf("backend: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidBackendID       = fmt.Errorf("backend: invalid backend_id: %w", commonerrors.ErrValidation)
	ErrInvalidEmbeddingConfig = fmt.Errorf("backend: invalid embedding config: %w", commonerrors.ErrValidation)
	ErrInvalidBackend         = fmt.Errorf("backend: invalid backend: %w", commonerrors.ErrValidation)
	ErrInvalidHealthChecks    = fmt.Errorf("backend: invalid health checks: %w", commonerrors.ErrValidation)
)
