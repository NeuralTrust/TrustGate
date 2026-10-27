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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	appconfig "github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type fakeGCPTokenSource struct {
	mutex   sync.Mutex
	calls   int
	expires time.Duration
	delay   time.Duration
	release chan struct{}
	err     error
}

func (s *fakeGCPTokenSource) Token() (*oauth2.Token, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	if s.release != nil {
		<-s.release
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &oauth2.Token{AccessToken: fmt.Sprintf("token-%d", s.calls), Expiry: time.Now().Add(s.expires)}, nil
}

func (s *fakeGCPTokenSource) requests() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.calls
}

func mustGCPStrategy(t *testing.T, source oauth2.TokenSource) poolAuthStrategy {
	t.Helper()
	strategy, err := newPoolAuthStrategy(t.Context(), &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginGCP}, authDependencies{
		loadGCPTokenSource: func(scopes ...string) (oauth2.TokenSource, error) {
			require.Equal(t, gcpDatabaseScopes, scopes)
			return source, nil
		},
	})
	require.NoError(t, err)
	return strategy
}

func TestGCPAuthStrategyRequestsCloudSQLAndAlloyDBScopes(t *testing.T) {
	require.ElementsMatch(t, []string{
		"https://www.googleapis.com/auth/sqlservice.login",
		"https://www.googleapis.com/auth/alloydb.login",
	}, gcpDatabaseScopes)
}

func TestGCPAuthStrategyReusesTokenUntilItNearlyExpires(t *testing.T) {
	source := &fakeGCPTokenSource{expires: time.Hour}
	poolConfig := mustPoolConfig(t)
	mustGCPStrategy(t, source)(poolConfig)
	require.Empty(t, poolConfig.ConnConfig.Password)

	for range 3 {
		connConfig := poolConfig.ConnConfig.Copy()
		require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
		require.Equal(t, "token-1", connConfig.Password)
	}
	require.Equal(t, 1, source.requests())
}

func TestGCPAuthStrategyRefreshesWithinTheMargin(t *testing.T) {
	source := &fakeGCPTokenSource{expires: gcpTokenRefreshMargin - time.Minute}
	poolConfig := mustPoolConfig(t)
	mustGCPStrategy(t, source)(poolConfig)

	for index := 1; index <= 2; index++ {
		connConfig := poolConfig.ConnConfig.Copy()
		require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
		require.Equal(t, fmt.Sprintf("token-%d", index), connConfig.Password)
	}
	require.Equal(t, 2, source.requests())
}

func TestGCPAuthStrategyFailsClosed(t *testing.T) {
	loadErr, tokenErr := errors.New("no application default credentials"), errors.New("metadata server rejected the request")

	t.Run("credential load error", func(t *testing.T) {
		strategy, err := newPoolAuthStrategy(t.Context(), &appconfig.DatabaseConfig{Login: appconfig.PostgresLoginGCP}, authDependencies{
			loadGCPTokenSource: func(...string) (oauth2.TokenSource, error) { return nil, loadErr },
		})
		require.ErrorIs(t, err, loadErr)
		require.Nil(t, strategy)
	})

	t.Run("token error has no fallback", func(t *testing.T) {
		poolConfig := mustPoolConfig(t)
		mustGCPStrategy(t, &fakeGCPTokenSource{expires: time.Hour, err: tokenErr})(poolConfig)
		connConfig := poolConfig.ConnConfig.Copy()
		err := poolConfig.BeforeConnect(t.Context(), connConfig)
		require.ErrorIs(t, err, tokenErr)
		require.Empty(t, connConfig.Password)
		require.Empty(t, poolConfig.ConnConfig.Password)
		require.NotContains(t, err.Error(), "static-password")
	})

	t.Run("empty token is rejected", func(t *testing.T) {
		poolConfig := mustPoolConfig(t)
		mustGCPStrategy(t, oauth2.StaticTokenSource(&oauth2.Token{}))(poolConfig)
		connConfig := poolConfig.ConnConfig.Copy()
		require.ErrorIs(t, poolConfig.BeforeConnect(t.Context(), connConfig), errGCPTokenEmpty)
		require.Empty(t, connConfig.Password)
	})

	t.Run("stuck fetch times out", func(t *testing.T) {
		source := &fakeGCPTokenSource{expires: time.Hour, release: make(chan struct{})}
		defer close(source.release)
		_, err := gcpToken(source, 10*time.Millisecond)
		require.ErrorIs(t, err, errGCPTokenTimeout)
	})
}

func TestGCPAuthStrategyConcurrentHooksShareOneToken(t *testing.T) {
	source := &fakeGCPTokenSource{expires: time.Hour, delay: 20 * time.Millisecond}
	poolConfig := mustPoolConfig(t)
	mustGCPStrategy(t, source)(poolConfig)
	for index := range 24 {
		t.Run(fmt.Sprintf("concurrent-%d", index), func(t *testing.T) {
			t.Parallel()
			connConfig := poolConfig.ConnConfig.Copy()
			require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
			require.Equal(t, "token-1", connConfig.Password)
		})
	}
	t.Cleanup(func() { require.Equal(t, 1, source.requests()) })
}

func TestGCPTokenFetchOutlivesTheConnectDeadline(t *testing.T) {
	source := &fakeGCPTokenSource{expires: time.Hour, delay: 50 * time.Millisecond}
	poolConfig := mustPoolConfig(t)
	poolConfig.ConnConfig.ConnectTimeout = 10 * time.Millisecond
	mustGCPStrategy(t, source)(poolConfig)

	connConfig := poolConfig.ConnConfig.Copy()
	require.NoError(t, poolConfig.BeforeConnect(t.Context(), connConfig))
	require.Equal(t, "token-1", connConfig.Password)
}

func TestBuildPoolConfigGCP(t *testing.T) {
	// An authorized_user file resolves through the real ADC loader without any
	// network call, unlike the metadata-server probe.
	credentials := filepath.Join(t.TempDir(), "adc.json")
	require.NoError(t, os.WriteFile(credentials, []byte(`{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"refresh"}`), 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credentials)
	cfg := &appconfig.DatabaseConfig{
		Login: appconfig.PostgresLoginGCP, Host: "db.example.com", Port: 5432,
		User: "trustgate-db@my-project.iam", Password: "'", Name: "trustgate", SSLMode: "require",
	}
	poolConfig, err := buildPoolConfig(t.Context(), cfg)
	require.NoError(t, err)
	require.Equal(t, "trustgate", poolConfig.ConnConfig.Database)
	require.Equal(t, "trustgate-db@my-project.iam", poolConfig.ConnConfig.User)
	require.Empty(t, poolConfig.ConnConfig.Password)
	require.NotNil(t, poolConfig.BeforeConnect)
}
