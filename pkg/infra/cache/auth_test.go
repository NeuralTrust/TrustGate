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
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/require"
)

func TestNewCredentialsProvider(t *testing.T) {
	loadErr := errors.New("load failed")
	tests := []struct {
		name      string
		cfg       Config
		region    string
		loadErr   error
		wantErr   error
		wantNil   bool
		wantLoads int
	}{
		{name: "default returns nil provider", cfg: Config{Login: "default"}, wantNil: true},
		{name: "empty login returns nil provider", cfg: Config{}, wantNil: true},
		{name: "aws load error is wrapped", cfg: Config{Login: "aws"}, loadErr: loadErr, wantErr: loadErr, wantNil: true, wantLoads: 1},
		{name: "aws empty region required", cfg: Config{Login: "aws"}, wantErr: errAWSRegionRequired, wantNil: true, wantLoads: 1},
		{name: "aws valid returns provider", cfg: Config{Login: "aws", Username: "iam-user", CacheName: "cache.example.com"}, region: "eu-west-1", wantLoads: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loads := 0
			provider, err := newCredentialsProvider(t.Context(), &tt.cfg, redisAuthDependencies{
				loadConfig: func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
					loads++
					return aws.Config{Region: tt.region, Credentials: aws.AnonymousCredentials{}}, tt.loadErr
				},
			})
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.wantLoads, loads)
			if tt.wantNil {
				require.Nil(t, provider)
				return
			}
			require.NotNil(t, provider)
		})
	}
}

func TestNewCredentialsProviderMintsFreshTokenPerCall(t *testing.T) {
	var mutex sync.Mutex
	calls := 0
	provider, err := newCredentialsProvider(t.Context(), &Config{
		Login:     "aws",
		Username:  "iam-user",
		CacheName: "cache.example.com",
	}, redisAuthDependencies{
		loadConfig: func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
			return aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}}, nil
		},
		buildToken: func(context.Context, string, string, string, bool, aws.CredentialsProvider) (string, error) {
			mutex.Lock()
			defer mutex.Unlock()
			calls++
			return fmt.Sprintf("token-%d", calls), nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, provider)

	for index := 1; index <= 3; index++ {
		user, token, providerErr := provider(t.Context())
		require.NoError(t, providerErr)
		require.Equal(t, "iam-user", user)
		require.Equal(t, fmt.Sprintf("token-%d", index), token)
	}

	const concurrent = 32
	for index := range concurrent {
		t.Run(fmt.Sprintf("concurrent-%d", index), func(t *testing.T) {
			t.Parallel()
			user, token, providerErr := provider(t.Context())
			require.NoError(t, providerErr)
			require.Equal(t, "iam-user", user)
			require.NotEmpty(t, token)
		})
	}
	t.Cleanup(func() {
		mutex.Lock()
		defer mutex.Unlock()
		require.Equal(t, concurrent+3, calls)
	})
}

func TestNewCredentialsProviderFailClosed(t *testing.T) {
	tokenErr := errors.New("token failed")
	secrets := []string{"iam-user", "cache.example.com", "fake-token", "eu-west-1"}
	provider, err := newCredentialsProvider(t.Context(), &Config{
		Login:     "aws",
		Username:  "iam-user",
		CacheName: "cache.example.com",
	}, redisAuthDependencies{
		loadConfig: func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
			return aws.Config{Region: "eu-west-1", Credentials: aws.AnonymousCredentials{}}, nil
		},
		buildToken: func(context.Context, string, string, string, bool, aws.CredentialsProvider) (string, error) {
			return "fake-token", tokenErr
		},
	})
	require.NoError(t, err)

	user, token, providerErr := provider(t.Context())
	require.ErrorIs(t, providerErr, tokenErr)
	require.Equal(t, []string{"", ""}, []string{user, token})
	for _, secret := range secrets {
		require.NotContains(t, providerErr.Error(), secret)
	}
}

func TestBuildElastiCacheAuthToken(t *testing.T) {
	creds := credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "")
	tests := []struct {
		name           string
		serverless     bool
		wantResource   string
		wantResourceOK bool
	}{
		{name: "replication group omits resource type", serverless: false},
		{name: "serverless adds resource type", serverless: true, wantResource: "ServerlessCache", wantResourceOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := buildElastiCacheAuthToken(t.Context(), "cache.example.com", "eu-west-1", "iam-user", tt.serverless, creds)
			require.NoError(t, err)
			require.False(t, strings.HasPrefix(token, "https://"))

			parsed, err := url.Parse("https://" + token)
			require.NoError(t, err)
			require.Equal(t, "cache.example.com", parsed.Host)

			query := parsed.Query()
			require.Equal(t, "connect", query.Get("Action"))
			require.Equal(t, "iam-user", query.Get("User"))
			require.Equal(t, "900", query.Get("X-Amz-Expires"))
			require.Equal(t, "AWS4-HMAC-SHA256", query.Get("X-Amz-Algorithm"))
			require.NotEmpty(t, query.Get("X-Amz-Credential"))
			require.NotEmpty(t, query.Get("X-Amz-Date"))
			require.NotEmpty(t, query.Get("X-Amz-Signature"))
			require.Contains(t, query.Get("X-Amz-Credential"), "elasticache")

			resource, ok := query["ResourceType"]
			require.Equal(t, tt.wantResourceOK, ok)
			if tt.wantResourceOK {
				require.Equal(t, []string{tt.wantResource}, resource)
			}
		})
	}
}
