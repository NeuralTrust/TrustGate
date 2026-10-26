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

package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type fakeGCPTokenSource struct {
	mutex   sync.Mutex
	calls   int
	current string
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
	token := s.current
	if token == "" {
		token = fmt.Sprintf("token-%d", s.calls)
	}
	return &oauth2.Token{AccessToken: token, Expiry: time.Now().Add(s.expires)}, nil
}

func (s *fakeGCPTokenSource) requests() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.calls
}

func (s *fakeGCPTokenSource) rotate(token string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.current = token
}

func gcpDeps(t *testing.T, source oauth2.TokenSource) redisAuthDependencies {
	t.Helper()
	return redisAuthDependencies{
		loadGCPTokenSource: func(scopes ...string) (oauth2.TokenSource, error) {
			require.Equal(t, gcpRedisScopes, scopes)
			return source, nil
		},
	}
}

func mustGCPProvider(t *testing.T, source oauth2.TokenSource) credentialsProvider {
	t.Helper()
	provider, err := newCredentialsProvider(t.Context(), &Config{Login: redisLoginGCP}, gcpDeps(t, source))
	require.NoError(t, err)
	require.NotNil(t, provider)
	return provider
}

func TestGCPCredentialsProviderRequestsTheCloudPlatformScope(t *testing.T) {
	require.Equal(t, []string{"https://www.googleapis.com/auth/cloud-platform"}, gcpRedisScopes)
}

func TestGCPCredentialsProviderSendsTheTokenAsPasswordWithoutUsername(t *testing.T) {
	provider := mustGCPProvider(t, &fakeGCPTokenSource{expires: time.Hour})
	user, password, err := provider(t.Context())
	require.NoError(t, err)
	require.Empty(t, user)
	require.Equal(t, "token-1", password)
}

func TestGCPCredentialsProviderReusesTokenUntilItNearlyExpires(t *testing.T) {
	source := &fakeGCPTokenSource{expires: time.Hour}
	provider := mustGCPProvider(t, source)
	for range 3 {
		_, password, err := provider(t.Context())
		require.NoError(t, err)
		require.Equal(t, "token-1", password)
	}
	require.Equal(t, 1, source.requests())
}

func TestGCPCredentialsProviderRefreshesWithinTheMargin(t *testing.T) {
	source := &fakeGCPTokenSource{expires: gcpTokenRefreshMargin - time.Minute}
	provider := mustGCPProvider(t, source)
	for index := 1; index <= 2; index++ {
		_, password, err := provider(t.Context())
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("token-%d", index), password)
	}
	require.Equal(t, 2, source.requests())
}

func TestGCPCredentialsProviderConcurrentConnectionsShareOneToken(t *testing.T) {
	source := &fakeGCPTokenSource{expires: time.Hour, delay: 20 * time.Millisecond}
	provider := mustGCPProvider(t, source)
	for index := range 24 {
		t.Run(fmt.Sprintf("concurrent-%d", index), func(t *testing.T) {
			t.Parallel()
			_, password, err := provider(t.Context())
			require.NoError(t, err)
			require.Equal(t, "token-1", password)
		})
	}
	t.Cleanup(func() { require.Equal(t, 1, source.requests()) })
}

func TestGCPCredentialsProviderFailsClosed(t *testing.T) {
	loadErr, tokenErr := errors.New("no application default credentials"), errors.New("metadata server rejected the request")

	t.Run("credential load error", func(t *testing.T) {
		provider, err := newCredentialsProvider(t.Context(), &Config{Login: redisLoginGCP, Password: "static-password"}, redisAuthDependencies{
			loadGCPTokenSource: func(...string) (oauth2.TokenSource, error) { return nil, loadErr },
		})
		require.ErrorIs(t, err, loadErr)
		require.Nil(t, provider)
	})

	t.Run("token error has no fallback", func(t *testing.T) {
		provider := mustGCPProvider(t, &fakeGCPTokenSource{expires: time.Hour, err: tokenErr})
		user, password, err := provider(t.Context())
		require.ErrorIs(t, err, tokenErr)
		require.Empty(t, user)
		require.Empty(t, password)
	})

	t.Run("empty token is rejected", func(t *testing.T) {
		provider := mustGCPProvider(t, oauth2.StaticTokenSource(&oauth2.Token{}))
		_, password, err := provider(t.Context())
		require.ErrorIs(t, err, errGCPTokenEmpty)
		require.Empty(t, password)
	})

	t.Run("stuck fetch times out", func(t *testing.T) {
		source := &fakeGCPTokenSource{expires: time.Hour, release: make(chan struct{})}
		defer close(source.release)
		_, err := gcpToken(source, 10*time.Millisecond)
		require.ErrorIs(t, err, errGCPTokenTimeout)
	})
}

func TestGCPCredentialsProviderIgnoresTheConnectionDeadline(t *testing.T) {
	source := &fakeGCPTokenSource{expires: time.Hour, delay: 50 * time.Millisecond}
	provider := mustGCPProvider(t, source)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, password, err := provider(ctx)
	require.NoError(t, err)
	require.Equal(t, "token-1", password)
}

func TestDefaultGCPTokenSourceResolvesApplicationDefaultCredentials(t *testing.T) {
	credentials := filepath.Join(t.TempDir(), "adc.json")
	require.NoError(t, os.WriteFile(credentials, []byte(`{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"refresh"}`), 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credentials)
	source, err := defaultGCPTokenSource(gcpRedisScopes...)
	require.NoError(t, err)
	require.NotNil(t, source)
}
