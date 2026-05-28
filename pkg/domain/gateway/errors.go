package gateway

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

// Sentinel errors for the gateway aggregate. They wrap the package-wide
// sentinels in pkg/common/errors so callers can match either the
// generic or the entity-specific error via errors.Is.
var (
	ErrNotFound           = fmt.Errorf("gateway: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists      = fmt.Errorf("gateway: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents      = fmt.Errorf("gateway: %w", commonerrors.ErrHasDependents)
	ErrInvalidName        = fmt.Errorf("gateway: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidDescription = fmt.Errorf("gateway: invalid description: %w", commonerrors.ErrValidation)
)
