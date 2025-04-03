package domain

import (
	"fmt"

	"github.com/google/uuid"
)

var ErrEntityNotFound *notFoundError

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
