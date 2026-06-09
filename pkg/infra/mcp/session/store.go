// Package session persists upstream MCP session pins in Redis so any gateway
// replica can resume the same upstream session (idle TTL acts as the reaper).
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	"github.com/go-redis/redis/v8"
)

const (
	keyPrefix  = "mcp:upstream-session:"
	defaultTTL = 30 * time.Minute
)

var _ appmcp.SessionStore = (*Store)(nil)

type Store struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewStore(rdb *redis.Client) *Store {
	return &Store{rdb: rdb, ttl: defaultTTL}
}

func (s *Store) Get(ctx context.Context, key string) (*appmcp.Pin, error) {
	raw, err := s.rdb.Get(ctx, keyPrefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mcp session store: get: %w", err)
	}
	var pin appmcp.Pin
	if err := json.Unmarshal(raw, &pin); err != nil {
		return nil, fmt.Errorf("mcp session store: decode: %w", err)
	}
	// Refresh the idle TTL on use (best effort).
	_ = s.rdb.Expire(ctx, keyPrefix+key, s.ttl).Err()
	return &pin, nil
}

func (s *Store) Set(ctx context.Context, key string, pin appmcp.Pin) error {
	raw, err := json.Marshal(pin)
	if err != nil {
		return fmt.Errorf("mcp session store: encode: %w", err)
	}
	if err := s.rdb.Set(ctx, keyPrefix+key, raw, s.ttl).Err(); err != nil {
		return fmt.Errorf("mcp session store: set: %w", err)
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	if err := s.rdb.Del(ctx, keyPrefix+key).Err(); err != nil {
		return fmt.Errorf("mcp session store: delete: %w", err)
	}
	return nil
}
