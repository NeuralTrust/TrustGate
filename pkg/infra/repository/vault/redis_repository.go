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

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/go-redis/redis/v8"
)

var _ domain.Repository = (*redisRepository)(nil)

const (
	redisKeyPrefix     = "vault"
	redisScanBatchSize = 100
)

type redisRepository struct {
	rc     *redis.Client
	cipher domain.Encrypter
}

func NewRedisRepository(rc *redis.Client, cipher domain.Encrypter) *redisRepository {
	return &redisRepository{rc: rc, cipher: cipher}
}

type storedCredential struct {
	ID           ids.VaultID   `json:"id"`
	GatewayID    ids.GatewayID `json:"gateway_id"`
	PrincipalSub string        `json:"principal_sub"`
	Provider     string        `json:"provider"`
	AccountRef   string        `json:"account_ref"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	Scopes       []string      `json:"scopes"`
	ExpiresAt    *time.Time    `json:"expires_at"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

func (s *storedCredential) matches(gatewayID ids.GatewayID, principalSub, provider string) bool {
	return s.GatewayID == gatewayID && s.PrincipalSub == principalSub && s.Provider == provider
}

func (r *redisRepository) Upsert(ctx context.Context, c *domain.Credential) error {
	if c == nil {
		return errors.New("vault repository: nil credential")
	}
	access, err := r.cipher.Encrypt(c.AccessToken)
	if err != nil {
		return fmt.Errorf("vault repository: encrypt access token: %w", err)
	}
	refresh, err := r.cipher.Encrypt(c.RefreshToken)
	if err != nil {
		return fmt.Errorf("vault repository: encrypt refresh token: %w", err)
	}
	key := redisKey(c.GatewayID, c.PrincipalSub, c.Provider)
	existing, err := r.load(ctx, key)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	id := c.ID
	createdAt := c.CreatedAt
	if existing != nil {
		id = existing.ID
		createdAt = existing.CreatedAt
		if refresh == "" {
			refresh = existing.RefreshToken
		}
	}
	stored := storedCredential{
		ID:           id,
		GatewayID:    c.GatewayID,
		PrincipalSub: c.PrincipalSub,
		Provider:     c.Provider,
		AccountRef:   c.AccountRef,
		AccessToken:  access,
		RefreshToken: refresh,
		Scopes:       c.Scopes,
		ExpiresAt:    nullableTime(c.ExpiresAt),
		CreatedAt:    createdAt,
		UpdatedAt:    time.Now().UTC(),
	}
	payload, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("vault repository: marshal credential: %w", err)
	}
	if err := r.rc.Set(ctx, key, payload, 0).Err(); err != nil {
		return fmt.Errorf("vault repository: set: %w", err)
	}
	return nil
}

func (r *redisRepository) Find(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) (*domain.Credential, error) {
	stored, err := r.load(ctx, redisKey(gatewayID, principalSub, provider))
	if err != nil {
		return nil, err
	}
	if !stored.matches(gatewayID, principalSub, provider) {
		return nil, domain.ErrNotFound
	}
	return r.decrypt(stored)
}

func (r *redisRepository) ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*domain.Credential, error) {
	match := fmt.Sprintf("%s:%s:%s:*", redisKeyPrefix, escapeGlob(gatewayID.String()), escapeGlob(principalSub))
	var (
		cursor uint64
		out    []*domain.Credential
	)
	for {
		keys, next, err := r.rc.Scan(ctx, cursor, match, redisScanBatchSize).Result()
		if err != nil {
			return nil, fmt.Errorf("vault repository: scan: %w", err)
		}
		for _, key := range keys {
			stored, err := r.load(ctx, key)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					continue
				}
				return nil, err
			}
			if stored.GatewayID != gatewayID || stored.PrincipalSub != principalSub {
				continue
			}
			cred, err := r.decrypt(stored)
			if err != nil {
				return nil, err
			}
			out = append(out, cred)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Provider < out[j].Provider
	})
	return out, nil
}

func (r *redisRepository) Delete(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) error {
	key := redisKey(gatewayID, principalSub, provider)
	stored, err := r.load(ctx, key)
	if err != nil {
		return err
	}
	if !stored.matches(gatewayID, principalSub, provider) {
		return domain.ErrNotFound
	}
	if err := r.rc.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("vault repository: delete: %w", err)
	}
	return nil
}

func (r *redisRepository) load(ctx context.Context, key string) (*storedCredential, error) {
	val, err := r.rc.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("vault repository: get: %w", err)
	}
	var stored storedCredential
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		return nil, fmt.Errorf("vault repository: unmarshal credential: %w", err)
	}
	return &stored, nil
}

func (r *redisRepository) decrypt(stored *storedCredential) (*domain.Credential, error) {
	c := &domain.Credential{
		ID:           stored.ID,
		GatewayID:    stored.GatewayID,
		PrincipalSub: stored.PrincipalSub,
		Provider:     stored.Provider,
		AccountRef:   stored.AccountRef,
		Scopes:       stored.Scopes,
		CreatedAt:    stored.CreatedAt,
		UpdatedAt:    stored.UpdatedAt,
	}
	var err error
	if c.AccessToken, err = r.cipher.Decrypt(stored.AccessToken); err != nil {
		return nil, fmt.Errorf("%w: undecryptable access token for %s/%s: %v",
			domain.ErrNotFound, stored.PrincipalSub, stored.Provider, err)
	}
	if c.RefreshToken, err = r.cipher.Decrypt(stored.RefreshToken); err != nil {
		return nil, fmt.Errorf("%w: undecryptable refresh token for %s/%s: %v",
			domain.ErrNotFound, stored.PrincipalSub, stored.Provider, err)
	}
	if stored.ExpiresAt != nil {
		c.ExpiresAt = *stored.ExpiresAt
	}
	return c, nil
}

func redisKey(gatewayID ids.GatewayID, principalSub, provider string) string {
	return fmt.Sprintf("%s:%s:%s:%s", redisKeyPrefix, gatewayID.String(), principalSub, provider)
}

func escapeGlob(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`*`, `\*`,
		`?`, `\?`,
		`[`, `\[`,
		`]`, `\]`,
	)
	return replacer.Replace(s)
}
