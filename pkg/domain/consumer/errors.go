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
	ErrInvalidPolicyID  = fmt.Errorf("consumer: invalid policy_id: %w", commonerrors.ErrValidation)
	ErrInvalidAuthID    = fmt.Errorf("consumer: invalid auth_id: %w", commonerrors.ErrValidation)
	ErrInvalidName      = fmt.Errorf("consumer: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidType      = fmt.Errorf("consumer: invalid type: %w", commonerrors.ErrValidation)
	ErrInvalidPath      = fmt.Errorf("consumer: invalid path: %w", commonerrors.ErrValidation)
	ErrInvalidAlgorithm = fmt.Errorf("consumer: invalid algorithm: %w", commonerrors.ErrValidation)

	ErrInvalidEmbeddingConfig = fmt.Errorf("consumer: invalid embedding config: %w", commonerrors.ErrValidation)
	ErrPathAlreadyExists      = fmt.Errorf("consumer: path already exists: %w", commonerrors.ErrAlreadyExists)
	ErrNoBackends             = fmt.Errorf("consumer: at least one backend is required: %w", commonerrors.ErrValidation)
	ErrInvalidFallback        = fmt.Errorf("consumer: invalid fallback: %w", commonerrors.ErrValidation)
	ErrInvalidModelPolicy     = fmt.Errorf("consumer: invalid model policy: %w", commonerrors.ErrValidation)
)
