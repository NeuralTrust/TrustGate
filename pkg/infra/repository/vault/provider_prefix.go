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
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

var (
	_ domain.ProviderPrefixStore = (*Repository)(nil)
	_ domain.ProviderPrefixStore = (*redisRepository)(nil)
	_ domain.ProviderPrefixStore = (*fallbackRepository)(nil)
	_ domain.ReplicatedUpserter  = (*fallbackRepository)(nil)
)

// errEmptyProviderPrefix refuses a prefix that would match every credential.
var errEmptyProviderPrefix = errors.New("vault repository: provider prefix is required")

func (r *Repository) ListByProviderPrefix(ctx context.Context, gatewayID ids.GatewayID, prefix string) ([]domain.CredentialSummary, error) {
	if strings.TrimSpace(prefix) == "" {
		return nil, errEmptyProviderPrefix
	}
	const query = `
		SELECT principal_sub, provider, expires_at, created_at, updated_at
		FROM vault_credentials
		WHERE gateway_id = $1 AND provider LIKE $2 ESCAPE '\'
		ORDER BY principal_sub, provider`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID, likePrefix(prefix))
	if err != nil {
		return nil, fmt.Errorf("vault repository: list by provider prefix: %w", err)
	}
	defer rows.Close()
	var out []domain.CredentialSummary
	for rows.Next() {
		var s domain.CredentialSummary
		var expires *time.Time
		if err := rows.Scan(&s.PrincipalSub, &s.Provider, &expires, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("vault repository: scan summary: %w", err)
		}
		if expires != nil {
			s.ExpiresAt = *expires
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Repository) DeleteByProviderPrefix(ctx context.Context, gatewayID ids.GatewayID, prefix string) (int, error) {
	if strings.TrimSpace(prefix) == "" {
		return 0, errEmptyProviderPrefix
	}
	const query = `DELETE FROM vault_credentials WHERE gateway_id = $1 AND provider LIKE $2 ESCAPE '\'`
	deleted := 0
	err := database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, query, gatewayID, likePrefix(prefix))
		if err != nil {
			return err
		}
		deleted = int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("vault repository: delete by provider prefix: %w", err)
	}
	return deleted, nil
}

// scanProviderPrefix walks every credential of the gateway and hands the ones
// under prefix to visit. Keys cannot be split back into principal and provider
// (either may contain ':'), so each record is read; this is an admin path.
func (r *redisRepository) scanProviderPrefix(
	ctx context.Context,
	gatewayID ids.GatewayID,
	prefix string,
	visit func(key string, stored *storedCredential) error,
) error {
	if r == nil || r.rc == nil {
		return errors.New("vault repository: redis unavailable")
	}
	if strings.TrimSpace(prefix) == "" {
		return errEmptyProviderPrefix
	}
	match := fmt.Sprintf("%s:%s:*", redisKeyPrefix, escapeGlob(gatewayID.String()))
	return cache.ScanKeys(ctx, r.rc, match, redisScanBatchSize, func(ctx context.Context, keys []string) error {
		for _, key := range keys {
			stored, err := r.load(ctx, key)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					continue
				}
				return err
			}
			if stored.GatewayID != gatewayID || !strings.HasPrefix(stored.Provider, prefix) {
				continue
			}
			if err := visit(key, stored); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *redisRepository) ListByProviderPrefix(ctx context.Context, gatewayID ids.GatewayID, prefix string) ([]domain.CredentialSummary, error) {
	var out []domain.CredentialSummary
	err := r.scanProviderPrefix(ctx, gatewayID, prefix, func(_ string, stored *storedCredential) error {
		s := domain.CredentialSummary{
			PrincipalSub: stored.PrincipalSub,
			Provider:     stored.Provider,
			CreatedAt:    stored.CreatedAt,
			UpdatedAt:    stored.UpdatedAt,
		}
		if stored.ExpiresAt != nil {
			s.ExpiresAt = *stored.ExpiresAt
		}
		out = append(out, s)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("vault repository: list by provider prefix: %w", err)
	}
	sortSummaries(out)
	return out, nil
}

func (r *redisRepository) DeleteByProviderPrefix(ctx context.Context, gatewayID ids.GatewayID, prefix string) (int, error) {
	var keys []string
	err := r.scanProviderPrefix(ctx, gatewayID, prefix, func(key string, _ *storedCredential) error {
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("vault repository: delete by provider prefix: %w", err)
	}
	if len(keys) == 0 {
		return 0, nil
	}
	n, err := r.rc.Del(ctx, keys...).Result()
	if err != nil {
		return 0, fmt.Errorf("vault repository: delete by provider prefix: %w", err)
	}
	return int(n), nil
}

func (r *fallbackRepository) ListByProviderPrefix(ctx context.Context, gatewayID ids.GatewayID, prefix string) ([]domain.CredentialSummary, error) {
	merged := map[string]domain.CredentialSummary{}
	for _, store := range []domain.Repository{r.primary, r.fallback} {
		lister, ok := store.(domain.ProviderPrefixStore)
		if !ok {
			continue
		}
		list, err := lister.ListByProviderPrefix(ctx, gatewayID, prefix)
		if err != nil {
			return nil, err
		}
		for _, s := range list {
			key := s.PrincipalSub + "\x00" + s.Provider
			// The same value written to both stores is one value: keep the
			// newer write, which is what a reader sees.
			if prev, ok := merged[key]; ok && !s.UpdatedAt.After(prev.UpdatedAt) {
				continue
			}
			merged[key] = s
		}
	}
	out := make([]domain.CredentialSummary, 0, len(merged))
	for _, s := range merged {
		out = append(out, s)
	}
	sortSummaries(out)
	return out, nil
}

func (r *fallbackRepository) DeleteByProviderPrefix(ctx context.Context, gatewayID ids.GatewayID, prefix string) (int, error) {
	total := 0
	for _, store := range []domain.Repository{r.primary, r.fallback} {
		deleter, ok := store.(domain.ProviderPrefixStore)
		if !ok {
			continue
		}
		n, err := deleter.DeleteByProviderPrefix(ctx, gatewayID, prefix)
		if err != nil {
			return total, err
		}
		total = max(total, n)
	}
	return total, nil
}

// UpsertReplicated writes to both stores, so a value an admin sets on the
// control plane is read by the data plane, which only reads the shared Redis.
func (r *fallbackRepository) UpsertReplicated(ctx context.Context, c *domain.Credential) error {
	if err := r.primary.Upsert(ctx, c); err != nil {
		return err
	}
	return r.fallback.Upsert(ctx, c)
}

func sortSummaries(out []domain.CredentialSummary) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].PrincipalSub != out[j].PrincipalSub {
			return out[i].PrincipalSub < out[j].PrincipalSub
		}
		return out[i].Provider < out[j].Provider
	})
}
