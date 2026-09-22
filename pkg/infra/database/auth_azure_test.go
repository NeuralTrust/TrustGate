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
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	appconfig "github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/require"
)

type fakeAzureCredential struct {
	mutex     sync.Mutex
	calls     []policy.TokenRequestOptions
	expires   time.Duration
	refreshIn time.Duration
	delay     time.Duration
	failFrom  int
	err       error
}

func (c *fakeAzureCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return azcore.AccessToken{}, ctx.Err()
		}
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.calls = append(c.calls, options)
	if c.err != nil && len(c.calls) > c.failFrom {
		return azcore.AccessToken{}, c.err
	}
	token := azcore.AccessToken{Token: fmt.Sprintf("token-%d", len(c.calls)), ExpiresOn: time.Now().Add(c.expires)}
	if c.refreshIn != 0 {
		token.RefreshOn = time.Now().Add(c.refreshIn)
	}
	return token, nil
}

func (c *fakeAzureCredential) requests() []policy.TokenRequestOptions {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]policy.TokenRequestOptions(nil), c.calls...)
}

func mustAzureStrategy(t *testing.T, cfg *appconfig.DatabaseConfig, credential *fakeAzureCredential) poolAuthStrategy {
	t.Helper()
	strategy, err := newPoolAuthStrategy(t.Context(), cfg, authDependencies{
		loadAzureCredential: func() (azcore.TokenCredential, error) { return credential, nil },
	})
	require.NoError(t, err)
	return strategy
}

func TestAzureAuthStrategyReusesTokenUntilItNearlyExpires(t *testing.T) {
	credential := &fakeAzureCredential{expires: time.Hour}
	cfg := &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginAzure, AzureScope: "https://ossrdbms-aad.example.net/.default"}
	poolConfig := mustPoolConfig(t)
	mustAzureStrategy(t, cfg, credential)(poolConfig)
	require.Empty(t, poolConfig.ConnConfig.Password)

	for range 3 {
		connConfig := poolConfig.ConnConfig.Copy()
		require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
		require.Equal(t, "token-1", connConfig.Password)
	}
	requests := credential.requests()
	require.Len(t, requests, 1)
	require.Equal(t, []string{cfg.AzureScope}, requests[0].Scopes)
}

func TestAzureAuthStrategyRefreshesWithinTheMargin(t *testing.T) {
	credential := &fakeAzureCredential{expires: azureTokenRefreshMargin - time.Minute}
	cfg := &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginAzure}
	poolConfig := mustPoolConfig(t)
	mustAzureStrategy(t, cfg, credential)(poolConfig)

	for index := 1; index <= 2; index++ {
		connConfig := poolConfig.ConnConfig.Copy()
		require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
		require.Equal(t, fmt.Sprintf("token-%d", index), connConfig.Password)
	}
	requests := credential.requests()
	require.Len(t, requests, 2)
	require.Equal(t, []string{appconfig.DefaultAzureScope}, requests[0].Scopes)
}

func TestAzureAuthStrategyFailsClosed(t *testing.T) {
	loadErr, tokenErr := errors.New("credential unavailable"), errors.New("entra rejected the request")

	t.Run("credential load error", func(t *testing.T) {
		strategy, err := newPoolAuthStrategy(t.Context(), &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginAzure}, authDependencies{
			loadAzureCredential: func() (azcore.TokenCredential, error) { return nil, loadErr },
		})
		require.ErrorIs(t, err, loadErr)
		require.Nil(t, strategy)
	})

	t.Run("token error has no fallback", func(t *testing.T) {
		credential := &fakeAzureCredential{expires: time.Hour, err: tokenErr}
		poolConfig := mustPoolConfig(t)
		mustAzureStrategy(t, &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginAzure}, credential)(poolConfig)
		connConfig := poolConfig.ConnConfig.Copy()
		err := poolConfig.BeforeConnect(t.Context(), connConfig)
		require.ErrorIs(t, err, tokenErr)
		require.Empty(t, connConfig.Password)
		require.Empty(t, poolConfig.ConnConfig.Password)
		require.NotContains(t, err.Error(), "static-password")
	})
}

func TestAzureAuthStrategyConcurrentHooksShareOneToken(t *testing.T) {
	credential := &fakeAzureCredential{expires: time.Hour}
	poolConfig := mustPoolConfig(t)
	mustAzureStrategy(t, &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginAzure}, credential)(poolConfig)
	for index := range 32 {
		t.Run(fmt.Sprintf("concurrent-%d", index), func(t *testing.T) {
			t.Parallel()
			connConfig := poolConfig.ConnConfig.Copy()
			require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
			require.Equal(t, "token-1", connConfig.Password)
		})
	}
	t.Cleanup(func() { require.Len(t, credential.requests(), 1) })
}

func TestBuildPoolConfigAzureDoesNotParseStaticPassword(t *testing.T) {
	poolConfig, err := buildPoolConfig(t.Context(), &appconfig.DatabaseConfig{
		Login: appconfig.PostgresLoginAzure, Host: "db.postgres.database.azure.com", Port: 5432,
		User: "trustgate-identity", Password: "'", Name: "trustgate", SSLMode: "require",
	})
	require.NoError(t, err)
	require.Equal(t, "trustgate", poolConfig.ConnConfig.Database)
	require.Equal(t, "trustgate-identity", poolConfig.ConnConfig.User)
	require.Empty(t, poolConfig.ConnConfig.Password)
	require.NotNil(t, poolConfig.BeforeConnect)
}

func TestAzureTokenFetchOutlivesTheConnectDeadline(t *testing.T) {
	credential := &fakeAzureCredential{expires: time.Hour, delay: 50 * time.Millisecond}
	poolConfig := mustPoolConfig(t)
	poolConfig.ConnConfig.ConnectTimeout = 10 * time.Millisecond
	mustAzureStrategy(t, &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginAzure}, credential)(poolConfig)

	connConfig := poolConfig.ConnConfig.Copy()
	require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
	require.Equal(t, "token-1", connConfig.Password)
}

func TestAzureAuthStrategyKeepsAValidTokenWhenRefreshFails(t *testing.T) {
	credential := &fakeAzureCredential{
		expires:  azureTokenRefreshMargin - time.Minute,
		failFrom: 1,
		err:      errors.New("entra throttled the request"),
	}
	poolConfig := mustPoolConfig(t)
	mustAzureStrategy(t, &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginAzure}, credential)(poolConfig)

	for range 2 {
		connConfig := poolConfig.ConnConfig.Copy()
		require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
		require.Equal(t, "token-1", connConfig.Password)
	}
	require.Len(t, credential.requests(), 2)
}

func TestAzureAuthStrategyHonoursRefreshOn(t *testing.T) {
	credential := &fakeAzureCredential{expires: 24 * time.Hour, refreshIn: -time.Minute}
	poolConfig := mustPoolConfig(t)
	mustAzureStrategy(t, &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginAzure}, credential)(poolConfig)

	for index := 1; index <= 2; index++ {
		connConfig := poolConfig.ConnConfig.Copy()
		require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
		require.Equal(t, fmt.Sprintf("token-%d", index), connConfig.Password)
	}
	require.Len(t, credential.requests(), 2)
}
