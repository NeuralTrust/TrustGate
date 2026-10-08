// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/redis/go-redis/v9"
)

const (
	personalKeyTicketPrefix  = "oauth:personal-key:ticket:"
	personalKeySessionPrefix = "oauth:personal-key:session:"
)

// PersonalKeyPageStore keeps the MCP Store personal key page's tickets and
// browser sessions in Redis, for as long as a link lives.
type PersonalKeyPageStore struct {
	rdb *redis.Client
}

var _ appoauth.PersonalKeyPageStore = (*PersonalKeyPageStore)(nil)

func NewPersonalKeyPageStore(rdb *redis.Client) *PersonalKeyPageStore {
	return &PersonalKeyPageStore{rdb: rdb}
}

func (s *PersonalKeyPageStore) SaveTicket(ctx context.Context, id string, t appoauth.PersonalKeyTicket) error {
	return s.set(ctx, personalKeyTicketPrefix+id, t)
}

func (s *PersonalKeyPageStore) GetTicket(ctx context.Context, id string) (*appoauth.PersonalKeyTicket, error) {
	var t appoauth.PersonalKeyTicket
	found, err := s.get(ctx, personalKeyTicketPrefix+id, &t)
	if err != nil || !found {
		return nil, err
	}
	return &t, nil
}

func (s *PersonalKeyPageStore) DeleteTicket(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, personalKeyTicketPrefix+id).Err()
}

func (s *PersonalKeyPageStore) SaveSession(ctx context.Context, id string, session appoauth.PersonalKeySession) error {
	return s.set(ctx, personalKeySessionPrefix+id, session)
}

func (s *PersonalKeyPageStore) GetSession(ctx context.Context, id string) (*appoauth.PersonalKeySession, error) {
	var session appoauth.PersonalKeySession
	found, err := s.get(ctx, personalKeySessionPrefix+id, &session)
	if err != nil || !found {
		return nil, err
	}
	return &session, nil
}

func (s *PersonalKeyPageStore) DeleteSession(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, personalKeySessionPrefix+id).Err()
}

func (s *PersonalKeyPageStore) set(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("personal key store: encode: %w", err)
	}
	return s.rdb.Set(ctx, key, raw, appoauth.PersonalKeyTicketTTL).Err()
}

func (s *PersonalKeyPageStore) get(ctx context.Context, key string, v any) (bool, error) {
	raw, err := s.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("personal key store: load: %w", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("personal key store: decode: %w", err)
	}
	return true, nil
}
