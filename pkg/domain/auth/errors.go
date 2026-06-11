package auth

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrNotFound         = fmt.Errorf("auth: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists    = fmt.Errorf("auth: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents    = fmt.Errorf("auth: %w", commonerrors.ErrHasDependents)
	ErrInvalidName      = fmt.Errorf("auth: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidGatewayID = fmt.Errorf("auth: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidType      = fmt.Errorf("auth: invalid type: %w", commonerrors.ErrValidation)
	ErrInvalidConfig    = fmt.Errorf("auth: invalid config: %w", commonerrors.ErrValidation)
	// ErrDuplicateOAuth2 rejects a second enabled oauth2 Auth covering the
	// same (issuer, audience): inbound tokens could not be attributed to one
	// entry deterministically. Scope each entry with distinct audiences, or
	// disable one of them.
	ErrDuplicateOAuth2 = fmt.Errorf("auth: another enabled oauth2 auth already covers this issuer and audience: %w", commonerrors.ErrAlreadyExists)
)
