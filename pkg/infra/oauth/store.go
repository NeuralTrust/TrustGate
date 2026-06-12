package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/go-redis/redis/v8"
)

const (
	pendingPrefix = "oauth:pending:"
	codePrefix    = "oauth:code:"
	pendingTTL    = 10 * time.Minute
	codeTTL       = 5 * time.Minute
)

var _ appoauth.FlowStore = (*Store)(nil)

type Store struct {
	rdb *redis.Client
}

func NewStore(rdb *redis.Client) *Store {
	return &Store{rdb: rdb}
}

func (s *Store) SavePending(ctx context.Context, state string, p appoauth.PendingAuthorization) error {
	return s.save(ctx, pendingPrefix+state, p, pendingTTL)
}

func (s *Store) TakePending(ctx context.Context, state string) (*appoauth.PendingAuthorization, error) {
	var p appoauth.PendingAuthorization
	ok, err := s.take(ctx, pendingPrefix+state, &p)
	if err != nil || !ok {
		return nil, err
	}
	return &p, nil
}

func (s *Store) SaveCode(ctx context.Context, code string, g appoauth.CodeGrant) error {
	return s.save(ctx, codePrefix+code, g, codeTTL)
}

func (s *Store) TakeCode(ctx context.Context, code string) (*appoauth.CodeGrant, error) {
	var g appoauth.CodeGrant
	ok, err := s.take(ctx, codePrefix+code, &g)
	if err != nil || !ok {
		return nil, err
	}
	return &g, nil
}

func (s *Store) save(ctx context.Context, key string, v any, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("oauth flow store: encode: %w", err)
	}
	if err := s.rdb.Set(ctx, key, raw, ttl).Err(); err != nil {
		return fmt.Errorf("oauth flow store: set: %w", err)
	}
	return nil
}

func (s *Store) take(ctx context.Context, key string, out any) (bool, error) {
	raw, err := s.rdb.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("oauth flow store: getdel: %w", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, fmt.Errorf("oauth flow store: decode: %w", err)
	}
	return true, nil
}
