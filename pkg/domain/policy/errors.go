package policy

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrNotFound         = fmt.Errorf("policy: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists    = fmt.Errorf("policy: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents    = fmt.Errorf("policy: %w", commonerrors.ErrHasDependents)
	ErrInvalidName       = fmt.Errorf("policy: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidGatewayID  = fmt.Errorf("policy: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidConsumerID = fmt.Errorf("policy: invalid consumer_id: %w", commonerrors.ErrValidation)
	ErrInvalidSlug       = fmt.Errorf("policy: invalid slug: %w", commonerrors.ErrValidation)
	ErrInvalidStage      = fmt.Errorf("policy: invalid stage: %w", commonerrors.ErrValidation)
	ErrInvalidPriority   = fmt.Errorf("policy: invalid priority: %w", commonerrors.ErrValidation)
)
