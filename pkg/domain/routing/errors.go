package routing

import (
	"errors"
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrInvalidModelRef  = fmt.Errorf("routing: invalid model reference: %w", commonerrors.ErrValidation)
	ErrUnknownPoolAlias = fmt.Errorf("routing: unknown pool alias: %w", commonerrors.ErrValidation)
	ErrAmbiguousModel   = fmt.Errorf("routing: ambiguous model: %w", commonerrors.ErrValidation)
	ErrModelDenied      = errors.New("routing: model denied")
)
