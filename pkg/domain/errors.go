package domain

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var (
	ErrEntityNotFound    *notFoundError
	ErrInvalidRuleType   = errors.New("invalid rule_type, must be 'agent' or 'endpoint'")
	ErrRuleAlreadyExists = errors.New("rule already exists")
)

type notFoundError struct {
	EntityType string
	ID         uuid.UUID
}

func (e *notFoundError) Error() string {
	return fmt.Sprintf("%s with ID '%s' not found", e.EntityType, e.ID.String())
}

func NewNotFoundError(entityType string, id uuid.UUID) error {
	return &notFoundError{
		EntityType: entityType,
		ID:         id,
	}
}

func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	var notFoundError *notFoundError
	ok := errors.As(err, &notFoundError)
	return ok
}
