package session

import (
	"context"

	"github.com/google/uuid"
)

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=session_repository_mock.go --case=underscore --with-expecter

type Repository interface {
	Save(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, sessionID string, gatewayID uuid.UUID) ([]*Session, error)
	GetAll(ctx context.Context, gatewayID uuid.UUID) ([]*Session, error)
	Delete(ctx context.Context, sessionID string, gatewayID uuid.UUID) error
}
