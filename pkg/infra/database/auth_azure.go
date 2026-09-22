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

package database

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/jackc/pgx/v5"
)

const (
	azureTokenRefreshMargin = 5 * time.Minute
	azureTokenFetchTimeout  = 20 * time.Second
	azureTokenMinValidity   = 30 * time.Second
)

type azureCredentialLoader func() (azcore.TokenCredential, error)

func defaultAzureCredential() (azcore.TokenCredential, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create azure default credential: %w", err)
	}
	return credential, nil
}

func newAzureAuthStrategy(_ context.Context, cfg *config.DatabaseConfig, dependencies authDependencies) (poolAuthStrategy, error) {
	credential, err := dependencies.loadAzureCredential()
	if err != nil {
		return nil, fmt.Errorf("load azure database authentication credential: %w", err)
	}
	scope := cfg.AzureScope
	if scope == "" {
		scope = config.DefaultAzureScope
	}
	tokens := &azureTokenCache{credential: credential, scope: scope}
	return newTokenAuthStrategy(func(ctx context.Context, _ *pgx.ConnConfig) (string, error) {
		return tokens.token(ctx)
	}), nil
}

type azureTokenCache struct {
	credential azcore.TokenCredential
	scope      string
	mutex      sync.Mutex
	cached     azcore.AccessToken
}

func (c *azureTokenCache) token(ctx context.Context) (string, error) {
	// The lock is held across GetToken so that a burst of new pooled connections
	// collapses into a single token request instead of one per connection.
	c.mutex.Lock()
	defer c.mutex.Unlock()
	now := time.Now()
	if c.fresh(now) {
		return c.cached.Token, nil
	}
	// The fetch must not inherit one connection's ConnectTimeout: waiters block on
	// an uncancellable mutex, so a deadline that started before the wait would be
	// spent by the time they get here and the whole burst would fail.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), azureTokenFetchTimeout)
	defer cancel()
	token, err := c.credential.GetToken(fetchCtx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	if err != nil {
		// A failed refresh must not discard a token Entra still accepts. This is not
		// a credential downgrade: DB_PASSWORD is never a fallback on this path.
		if c.cached.Token != "" && now.Add(azureTokenMinValidity).Before(c.cached.ExpiresOn) {
			return c.cached.Token, nil
		}
		return "", err
	}
	c.cached = token
	return token.Token, nil
}

func (c *azureTokenCache) fresh(now time.Time) bool {
	if c.cached.Token == "" {
		return false
	}
	// RefreshOn is the issuer's own hint to renew early; azcore leaves it zero when
	// the credential does not provide one.
	if !c.cached.RefreshOn.IsZero() && !now.Before(c.cached.RefreshOn) {
		return false
	}
	return now.Add(azureTokenRefreshMargin).Before(c.cached.ExpiresOn)
}
