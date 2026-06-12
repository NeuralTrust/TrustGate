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
	ticketPrefix  = "oauth:connect:ticket:"
	connectPrefix = "oauth:connect:state:"
	clientPrefix  = "oauth:dcr:client:"
	ticketTTL     = 15 * time.Minute
	connectTTL    = 10 * time.Minute
)

var (
	_ appoauth.ConnectStore = (*ConnectStore)(nil)
	_ appoauth.ClientStore  = (*ConnectStore)(nil)
)

type ConnectStore struct {
	rdb *redis.Client
}

func NewConnectStore(rdb *redis.Client) *ConnectStore {
	return &ConnectStore{rdb: rdb}
}

func (s *ConnectStore) SaveTicket(ctx context.Context, id string, t appoauth.ConnectTicket) error {
	return s.set(ctx, ticketPrefix+id, t, ticketTTL)
}

func (s *ConnectStore) GetTicket(ctx context.Context, id string) (*appoauth.ConnectTicket, error) {
	var t appoauth.ConnectTicket
	raw, err := s.rdb.Get(ctx, ticketPrefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: get: %w", err)
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("oauth connect store: decode: %w", err)
	}
	return &t, nil
}

func (s *ConnectStore) SaveConnect(ctx context.Context, state string, c appoauth.ConnectState) error {
	return s.set(ctx, connectPrefix+state, c, connectTTL)
}

func (s *ConnectStore) TakeConnect(ctx context.Context, state string) (*appoauth.ConnectState, error) {
	raw, err := s.rdb.GetDel(ctx, connectPrefix+state).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: getdel: %w", err)
	}
	var c appoauth.ConnectState
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("oauth connect store: decode: %w", err)
	}
	return &c, nil
}

func (s *ConnectStore) SaveClient(ctx context.Context, key string, c appoauth.RegisteredClient) error {
	return s.set(ctx, clientPrefix+key, c, 0)
}

func (s *ConnectStore) GetClient(ctx context.Context, key string) (*appoauth.RegisteredClient, error) {
	raw, err := s.rdb.Get(ctx, clientPrefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: get client: %w", err)
	}
	var c appoauth.RegisteredClient
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("oauth connect store: decode client: %w", err)
	}
	return &c, nil
}

func (s *ConnectStore) set(ctx context.Context, key string, v any, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("oauth connect store: encode: %w", err)
	}
	if err := s.rdb.Set(ctx, key, raw, ttl).Err(); err != nil {
		return fmt.Errorf("oauth connect store: set: %w", err)
	}
	return nil
}
