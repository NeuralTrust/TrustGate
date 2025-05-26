package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/session"
	"github.com/google/uuid"
)

const (
	SessionKeyPattern = "session:%s:%s"
)

type SessionRepository struct {
	cache common.Cache
}

func NewSessionRepository(cache common.Cache) session.Repository {
	return &SessionRepository{
		cache: cache,
	}
}
func (r *SessionRepository) SaveSession(ctx context.Context, session *session.Session) error {
	sessionKey := fmt.Sprintf(SessionKeyPattern, session.GatewayID.String(), session.ID)

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttl := session.ExpiresAt.Sub(time.Now())
	if ttl <= 0 {
		ttl = time.Hour
	}

	return r.cache.Set(ctx, sessionKey, string(sessionJSON), ttl)
}

func (r *SessionRepository) GetSessionsByID(ctx context.Context, sessionID string, gatewayID uuid.UUID) ([]*session.Session, error) {
	sessionKeyPattern := fmt.Sprintf(SessionKeyPattern, gatewayID.String(), sessionID)

	var cursor uint64
	var sessions []*session.Session

	for {
		keys, nextCursor, err := r.cache.Client().Scan(ctx, cursor, sessionKeyPattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("error scanning keys: %w", err)
		}

		for _, key := range keys {
			sessionJSON, err := r.cache.Get(ctx, key)
			if err != nil {
				continue
			}

			var s session.Session
			if err := json.Unmarshal([]byte(sessionJSON), &s); err != nil {
				continue
			}

			sessions = append(sessions, &s)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return sessions, nil
}

func (r *SessionRepository) GetAllSessions(ctx context.Context, gatewayID uuid.UUID) ([]*session.Session, error) {
	sessionKeyPattern := fmt.Sprintf(SessionKeyPattern, gatewayID.String(), "*")

	var cursor uint64
	var sessions []*session.Session

	for {
		keys, nextCursor, err := r.cache.Client().Scan(ctx, cursor, sessionKeyPattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("error scanning keys: %w", err)
		}

		for _, key := range keys {
			sessionJSON, err := r.cache.Get(ctx, key)
			if err != nil {
				continue
			}

			var s session.Session
			if err := json.Unmarshal([]byte(sessionJSON), &s); err != nil {
				continue
			}

			sessions = append(sessions, &s)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return sessions, nil
}

func (r *SessionRepository) DeleteSession(ctx context.Context, sessionID string, gatewayID uuid.UUID) error {
	sessionKey := fmt.Sprintf(SessionKeyPattern, gatewayID.String(), sessionID)
	return r.cache.Delete(ctx, sessionKey)
}
