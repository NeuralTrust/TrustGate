// Package gateway is the control-plane aggregate that owns a logical
// AI traffic boundary. A Gateway has one or more Backends attached to
// it. The aggregate is infra-free: it only knows how to construct and
// mutate itself.
package gateway

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	MaxNameLength        = 255
	MaxDescriptionLength = 4096
)

// Gateway is the control-plane aggregate root.
type Gateway struct {
	ID          uuid.UUID
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// New constructs a Gateway with a freshly generated UUID and current
// timestamps. It enforces name/description bounds; an invalid input
// returns ErrInvalidName or ErrInvalidDescription.
func New(name, description string) (*Gateway, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return nil, ErrInvalidName
	}
	if len(trimmedName) > MaxNameLength {
		return nil, ErrInvalidName
	}
	if len(description) > MaxDescriptionLength {
		return nil, ErrInvalidDescription
	}

	now := time.Now().UTC()
	return &Gateway{
		ID:          uuid.New(),
		Name:        trimmedName,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// Rehydrate reconstructs a Gateway from its persisted state without
// re-running validation. Use this exclusively from repositories.
func Rehydrate(id uuid.UUID, name, description string, createdAt, updatedAt time.Time) *Gateway {
	return &Gateway{
		ID:          id,
		Name:        name,
		Description: description,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

// Rename updates the gateway's name in-place, applying the same
// validation New() runs. UpdatedAt is bumped on success.
func (g *Gateway) Rename(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > MaxNameLength {
		return ErrInvalidName
	}
	g.Name = trimmed
	g.UpdatedAt = time.Now().UTC()
	return nil
}

// SetDescription updates the description in place. UpdatedAt is bumped
// on success.
func (g *Gateway) SetDescription(description string) error {
	if len(description) > MaxDescriptionLength {
		return ErrInvalidDescription
	}
	g.Description = description
	g.UpdatedAt = time.Now().UTC()
	return nil
}
