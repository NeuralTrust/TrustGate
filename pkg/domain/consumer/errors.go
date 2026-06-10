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
	ErrInvalidAuthID    = fmt.Errorf("consumer: invalid auth_id: %w", commonerrors.ErrValidation)
	ErrInvalidName      = fmt.Errorf("consumer: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidType      = fmt.Errorf("consumer: invalid type: %w", commonerrors.ErrValidation)
	ErrInvalidPath      = fmt.Errorf("consumer: invalid path: %w", commonerrors.ErrValidation)

	ErrInvalidRoutingMode = fmt.Errorf("consumer: invalid routing_mode: %w", commonerrors.ErrValidation)
	ErrInvalidLBConfig    = fmt.Errorf("consumer: invalid lb_config: %w", commonerrors.ErrValidation)
	ErrPathAlreadyExists  = fmt.Errorf("consumer: path already exists: %w", commonerrors.ErrAlreadyExists)
	ErrInvalidFallback    = fmt.Errorf("consumer: invalid fallback: %w", commonerrors.ErrValidation)
	ErrInvalidModelPolicy = fmt.Errorf("consumer: invalid model policy: %w", commonerrors.ErrValidation)
)
