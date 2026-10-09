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

const modelRequestTicketPrefix = "oauth:model-request:ticket:"

// ModelRequestStore keeps the MCP Store model request page's tickets in
// Redis, for as long as a link lives.
type ModelRequestStore struct {
	rdb *redis.Client
}

var _ appoauth.ModelRequestStore = (*ModelRequestStore)(nil)

func NewModelRequestStore(rdb *redis.Client) *ModelRequestStore {
	return &ModelRequestStore{rdb: rdb}
}

func (s *ModelRequestStore) SaveTicket(ctx context.Context, id string, t appoauth.ModelRequestTicket) error {
	raw, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("model request store: encode: %w", err)
	}
	return s.rdb.Set(ctx, modelRequestTicketPrefix+id, raw, appoauth.ModelRequestTicketTTL).Err()
}

func (s *ModelRequestStore) GetTicket(ctx context.Context, id string) (*appoauth.ModelRequestTicket, error) {
	raw, err := s.rdb.Get(ctx, modelRequestTicketPrefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t appoauth.ModelRequestTicket
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("model request store: decode: %w", err)
	}
	return &t, nil
}

func (s *ModelRequestStore) DeleteTicket(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, modelRequestTicketPrefix+id).Err()
}
