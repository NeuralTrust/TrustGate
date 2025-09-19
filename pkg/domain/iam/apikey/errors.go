package apikey

import (
	"fmt"

	"github.com/google/uuid"
)

var (
	ErrInvalidPolicyIDFormat  = fmt.Errorf("invalid policy ID format")
	ErrFailedToValidatePolicy = fmt.Errorf("failed to validate policies")
)

type MissingPoliciesError struct {
	Missing []uuid.UUID
}

func (e *MissingPoliciesError) Error() string {
	return fmt.Sprintf("some policies do not exist: missing=%v", e.Missing)
}
