package session

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	Save(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, sessionID string, gatewayID uuid.UUID) ([]*Session, error)
	GetAll(ctx context.Context, gatewayID uuid.UUID) ([]*Session, error)
	Delete(ctx context.Context, sessionID string, gatewayID uuid.UUID) error
}
