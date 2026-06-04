package session

import "context"

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=session_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, session *Session) error
	Get(ctx context.Context, gatewayID, sessionID string) (*Session, error)
}
