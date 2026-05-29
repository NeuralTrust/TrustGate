package consumer

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrNotFound         = fmt.Errorf("consumer: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists    = fmt.Errorf("consumer: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents    = fmt.Errorf("consumer: %w", commonerrors.ErrHasDependents)
	ErrInvalidGatewayID = fmt.Errorf("consumer: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidBackendID = fmt.Errorf("consumer: invalid backend_id: %w", commonerrors.ErrValidation)
	ErrInvalidName      = fmt.Errorf("consumer: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidType      = fmt.Errorf("consumer: invalid type: %w", commonerrors.ErrValidation)
	ErrInvalidPath      = fmt.Errorf("consumer: invalid path: %w", commonerrors.ErrValidation)
	ErrInvalidMethods   = fmt.Errorf("consumer: invalid methods: %w", commonerrors.ErrValidation)
	ErrInvalidRetries   = fmt.Errorf("consumer: invalid retry_attempts: %w", commonerrors.ErrValidation)
	ErrNoBackends       = fmt.Errorf("consumer: at least one backend is required: %w", commonerrors.ErrValidation)
)
