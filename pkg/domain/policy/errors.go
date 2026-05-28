package policy

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrNotFound         = fmt.Errorf("policy: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists    = fmt.Errorf("policy: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents    = fmt.Errorf("policy: %w", commonerrors.ErrHasDependents)
	ErrInvalidName      = fmt.Errorf("policy: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidGatewayID = fmt.Errorf("policy: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidPlugin    = fmt.Errorf("policy: invalid plugin: %w", commonerrors.ErrValidation)
	ErrInvalidStage     = fmt.Errorf("policy: invalid plugin stage: %w", commonerrors.ErrValidation)
	ErrDuplicatePlugin  = fmt.Errorf("policy: duplicate plugin (name, stage): %w", commonerrors.ErrValidation)
)
