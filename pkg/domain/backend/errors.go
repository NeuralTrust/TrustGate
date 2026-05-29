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
	ErrInvalidAlgorithm       = fmt.Errorf("backend: invalid algorithm: %w", commonerrors.ErrValidation)
	ErrInvalidEmbeddingConfig = fmt.Errorf("backend: invalid embedding config: %w", commonerrors.ErrValidation)
	ErrInvalidTarget          = fmt.Errorf("backend: invalid target: %w", commonerrors.ErrValidation)
	ErrInvalidHealthChecks    = fmt.Errorf("backend: invalid health checks: %w", commonerrors.ErrValidation)
	ErrNoTargets              = fmt.Errorf("backend: at least one target is required: %w", commonerrors.ErrValidation)
)
