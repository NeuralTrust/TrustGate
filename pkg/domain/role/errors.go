package role

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrNotFound           = fmt.Errorf("role: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists      = fmt.Errorf("role: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents      = fmt.Errorf("role: %w", commonerrors.ErrHasDependents)
	ErrInvalidGatewayID   = fmt.Errorf("role: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidName        = fmt.Errorf("role: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidRoleID      = fmt.Errorf("role: invalid role_id: %w", commonerrors.ErrValidation)
	ErrInvalidModelPolicy = fmt.Errorf("role: invalid model policy: %w", commonerrors.ErrValidation)
	ErrInvalidJSON        = fmt.Errorf("role: invalid json: %w", commonerrors.ErrValidation)
)
