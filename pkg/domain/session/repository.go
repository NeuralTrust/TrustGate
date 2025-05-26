package session

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	SaveSession(ctx context.Context, session *Session) error
	GetSessionsByID(ctx context.Context, sessionID string, gatewayID uuid.UUID) ([]*Session, error)
	GetAllSessions(ctx context.Context, gatewayID uuid.UUID) ([]*Session, error)
	DeleteSession(ctx context.Context, sessionID string, gatewayID uuid.UUID) error
}
