package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/session"
	"github.com/go-redis/redis/v8"
)

const (
	sessionKeyPattern = "session:%s:%s"
	fallbackTTL       = time.Hour
)

type repository struct {
	rdb *redis.Client
}

func NewRepository(rdb *redis.Client) domain.Repository {
	return &repository{rdb: rdb}
}

func (r *repository) Save(ctx context.Context, s *domain.Session) error {
	if s == nil {
		return fmt.Errorf("session is nil")
	}
	if s.ID == "" || s.GatewayID == "" {
		return fmt.Errorf("session id and gateway id are required")
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	ttl := time.Until(s.ExpiresAt)
	if ttl <= 0 {
		ttl = fallbackTTL
	}
	return r.rdb.Set(ctx, key(s.GatewayID, s.ID), payload, ttl).Err()
}

func (r *repository) Get(ctx context.Context, gatewayID, sessionID string) (*domain.Session, error) {
	raw, err := r.rdb.Get(ctx, key(gatewayID, sessionID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	var s domain.Session
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &s, nil
}

func key(gatewayID, sessionID string) string {
	return fmt.Sprintf(sessionKeyPattern, gatewayID, sessionID)
}
