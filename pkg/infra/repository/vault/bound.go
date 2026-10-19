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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/jackc/pgx/v5"
)

// ExistsBound reports whether this gateway holds any vault credential for a
// catalog code: an OAuth token stored under the code or its resource
// fingerprint, or a secret URL variable. The credential is not decrypted.
func (r *Repository) ExistsBound(ctx context.Context, gatewayID ids.GatewayID, code string) (bool, error) {
	if r == nil || r.conn == nil || r.conn.Pool == nil {
		return false, errors.New("vault repository: postgres unavailable")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM vault_credentials
			 WHERE gateway_id = $1
			   AND (
			        provider = $2
			     OR provider LIKE $3 ESCAPE '\'
			     OR provider LIKE $4 ESCAPE '\'
			   )
		)`
	var found bool
	err := r.conn.Pool.QueryRow(ctx, query,
		gatewayID,
		code,
		likePrefix(code+"|"),
		likePrefix("urlvar:"+code+":"),
	).Scan(&found)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("vault repository: bound credentials: %w", err)
	}
	return found, nil
}

func (r *redisRepository) ExistsBound(ctx context.Context, gatewayID ids.GatewayID, code string) (bool, error) {
	if r == nil || r.rc == nil {
		return false, errors.New("vault repository: redis unavailable")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	match := fmt.Sprintf("%s:%s:*", redisKeyPrefix, escapeGlob(gatewayID.String()))
	var cursor uint64
	for {
		keys, next, err := r.rc.Scan(ctx, cursor, match, redisScanBatchSize).Result()
		if err != nil {
			return false, fmt.Errorf("vault repository: scan bound credentials: %w", err)
		}
		for _, key := range keys {
			stored, err := r.load(ctx, key)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					continue
				}
				return false, err
			}
			if stored.GatewayID != gatewayID {
				continue
			}
			if providerBoundToCode(stored.Provider, code) {
				return true, nil
			}
		}
		cursor = next
		if cursor == 0 {
			return false, nil
		}
	}
}

func (r *fallbackRepository) ExistsBound(ctx context.Context, gatewayID ids.GatewayID, code string) (bool, error) {
	if r == nil || r.primary == nil || r.fallback == nil {
		return false, errors.New("vault repository: fallback unavailable")
	}
	primary, ok := r.primary.(interface {
		ExistsBound(context.Context, ids.GatewayID, string) (bool, error)
	})
	if !ok {
		return false, errors.New("vault repository: primary cannot check bound credentials")
	}
	secondary, ok := r.fallback.(interface {
		ExistsBound(context.Context, ids.GatewayID, string) (bool, error)
	})
	if !ok {
		return false, errors.New("vault repository: fallback cannot check bound credentials")
	}
	found, err := primary.ExistsBound(ctx, gatewayID, code)
	if err != nil || found {
		return found, err
	}
	return secondary.ExistsBound(ctx, gatewayID, code)
}

func providerBoundToCode(provider, code string) bool {
	code = strings.TrimSpace(code)
	provider = strings.TrimSpace(provider)
	if code == "" || provider == "" {
		return false
	}
	if provider == code {
		return true
	}
	if strings.HasPrefix(provider, code+"|") {
		return true
	}
	return strings.HasPrefix(provider, "urlvar:"+code+":")
}

func likePrefix(prefix string) string {
	return escapeLike(prefix) + "%"
}

func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}
