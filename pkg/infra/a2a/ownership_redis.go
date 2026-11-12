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

package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/redis/go-redis/v9"
)

var _ appa2a.OwnershipStore = (*ownershipStore)(nil)

type ownershipStore struct {
	rdb redis.UniversalClient
}

// NewOwnershipStore keeps task and context owners in Redis under
// a2a:own:{gateway}:{registry}:{t|c}:{id}.
func NewOwnershipStore(rdb redis.UniversalClient) appa2a.OwnershipStore {
	return &ownershipStore{rdb: rdb}
}

func ownershipKey(k appa2a.OwnershipKey) string {
	return "a2a:own:" + k.GatewayID.String() + ":" + k.RegistryID.String() + ":" + k.Scope + ":" + k.ID
}

func (s *ownershipStore) Owner(ctx context.Context, key appa2a.OwnershipKey) (*appa2a.Owner, error) {
	raw, err := s.rdb.Get(ctx, ownershipKey(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("a2a ownership store: get: %w", err)
	}
	var o appa2a.Owner
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("a2a ownership store: decode: %w", err)
	}
	return &o, nil
}

func (s *ownershipStore) Claim(ctx context.Context, key appa2a.OwnershipKey, o appa2a.Owner, ttl time.Duration) (bool, *appa2a.Owner, error) {
	raw, err := json.Marshal(o)
	if err != nil {
		return false, nil, fmt.Errorf("a2a ownership store: encode: %w", err)
	}
	claimed, err := s.rdb.SetNX(ctx, ownershipKey(key), raw, ttl).Result()
	if err != nil {
		return false, nil, fmt.Errorf("a2a ownership store: setnx: %w", err)
	}
	if claimed {
		return true, nil, nil
	}
	existing, err := s.Owner(ctx, key)
	return false, existing, err
}

func (s *ownershipStore) Touch(ctx context.Context, key appa2a.OwnershipKey, ttl time.Duration) error {
	if err := s.rdb.Expire(ctx, ownershipKey(key), ttl).Err(); err != nil {
		return fmt.Errorf("a2a ownership store: expire: %w", err)
	}
	return nil
}
