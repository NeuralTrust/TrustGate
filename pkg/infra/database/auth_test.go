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

	appconfig "github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestNewPoolAuthStrategy(t *testing.T) {
	loadErr := errors.New("load failed")
	tests := []struct {
		name, login, region string
		loadErr, wantErr    error
		wantLoads           int
	}{
		{name: "default parity", login: "default"},
		{name: "load error", login: "aws", loadErr: loadErr, wantErr: loadErr, wantLoads: 1},
		{name: "empty region", login: "aws", wantErr: errAWSRegionRequired, wantLoads: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loads := 0
			strategy, err := newPoolAuthStrategy(t.Context(), tt.login, authDependencies{
				loadConfig: func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
					loads++
					return aws.Config{Region: tt.region}, tt.loadErr
				},
			})
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.wantLoads, loads)
			if err != nil {
				return
			}
			poolConfig := mustPoolConfig(t)
			password := poolConfig.ConnConfig.Password
			strategy(poolConfig)
			require.Equal(t, password, poolConfig.ConnConfig.Password)
			require.Nil(t, poolConfig.BeforeConnect)
		})
	}
}
func TestAWSAuthStrategyHookBehavior(t *testing.T) {
	type tokenCall struct {
		ctx                    context.Context
		endpoint, region, user string
		credentials            aws.CredentialsProvider
	}
	provider := aws.AnonymousCredentials{}
	var mutex sync.Mutex
	var calls []tokenCall
	strategy, err := newPoolAuthStrategy(t.Context(), "aws", authDependencies{
		loadConfig: func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
			return aws.Config{Region: "eu-west-1", Credentials: provider}, nil
		},
		buildToken: func(ctx context.Context, endpoint, region, user string, credentials aws.CredentialsProvider) (string, error) {
			mutex.Lock()
			defer mutex.Unlock()
			token := fmt.Sprintf("token-%d", len(calls)+1)
			calls = append(calls, tokenCall{ctx, endpoint, region, user, credentials})
			return token, nil
		},
	})
	require.NoError(t, err)
	poolConfig := mustPoolConfig(t)
	poolConfig.MaxConns, poolConfig.MinConns = 17, 3
	poolConfig.MaxConnLifetime, poolConfig.MaxConnIdleTime = 2*time.Hour, 7*time.Minute
	poolConfig.HealthCheckPeriod = 11 * time.Second
	poolConfig.BeforeConnect = func(_ context.Context, config *pgx.ConnConfig) error {
		config.Host, config.Port, config.User = "2001:db8::1", 6432, "hook-user"
		return nil
	}
	settings := []any{poolConfig.ConnConfig.TLSConfig, poolConfig.MaxConns, poolConfig.MinConns, poolConfig.MaxConnLifetime, poolConfig.MaxConnIdleTime, poolConfig.HealthCheckPeriod}
	strategy(poolConfig)
	require.Empty(t, poolConfig.ConnConfig.Password)
	require.Equal(t, settings, []any{poolConfig.ConnConfig.TLSConfig, poolConfig.MaxConns, poolConfig.MinConns, poolConfig.MaxConnLifetime, poolConfig.MaxConnIdleTime, poolConfig.HealthCheckPeriod})
	type contextKey struct{}
	for index := 1; index <= 2; index++ {
		hookCtx := context.WithValue(t.Context(), contextKey{}, index)
		config := poolConfig.ConnConfig.Copy()
		require.NoError(t, poolConfig.BeforeConnect(hookCtx, config))
		require.Equal(t, fmt.Sprintf("token-%d", index), config.Password)
	}
	require.Len(t, calls, 2)
	for _, call := range calls {
		require.Equal(t, []string{"[2001:db8::1]:6432", "eu-west-1", "hook-user"}, []string{call.endpoint, call.region, call.user})
		require.Equal(t, provider, call.credentials)
	}
	require.Equal(t, []any{1, 2}, []any{calls[0].ctx.Value(contextKey{}), calls[1].ctx.Value(contextKey{})})
	const concurrentHooks = 32
	t.Cleanup(func() { require.Len(t, calls, concurrentHooks+2) })
	for index := range concurrentHooks {
		t.Run(fmt.Sprintf("concurrent-%d", index), func(t *testing.T) {
			t.Parallel()
			config := poolConfig.ConnConfig.Copy()
			require.NoError(t, poolConfig.BeforeConnect(t.Context(), config))
		})
	}
}
func TestBuildPoolConfigAWSDoesNotParseStaticPassword(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	poolConfig, err := buildPoolConfig(t.Context(), &appconfig.DatabaseConfig{Login: "aws", Host: "db.example.com", Port: 5432, User: "db-user", Password: "'", Name: "trustgate", SSLMode: "require"})
	require.NoError(t, err)
	require.Empty(t, poolConfig.ConnConfig.Password)
	require.NotNil(t, poolConfig.BeforeConnect)
}
func TestAWSAuthStrategyErrors(t *testing.T) {
	priorErr, tokenErr := errors.New("prior failed"), errors.New("token failed")
	tests := []struct {
		name              string
		previousHook      func(context.Context, *pgx.ConnConfig) error
		tokenErr, wantErr error
		wantCalls         int
	}{
		{name: "prior hook stops signing", previousHook: func(context.Context, *pgx.ConnConfig) error { return priorErr }, wantErr: priorErr},
		{name: "token error has no fallback", tokenErr: tokenErr, wantErr: tokenErr, wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builderCalls := 0
			strategy, err := newPoolAuthStrategy(t.Context(), "aws", authDependencies{
				loadConfig: func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
					return aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}}, nil
				},
				buildToken: func(context.Context, string, string, string, aws.CredentialsProvider) (string, error) {
					builderCalls++
					return "fake-token", tt.tokenErr
				},
			})
			require.NoError(t, err)
			poolConfig := mustPoolConfig(t)
			poolConfig.BeforeConnect = tt.previousHook
			strategy(poolConfig)
			config := poolConfig.ConnConfig.Copy()
			err = poolConfig.BeforeConnect(t.Context(), config)
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.wantCalls, builderCalls)
			require.Equal(t, []string{"", ""}, []string{poolConfig.ConnConfig.Password, config.Password})
			for _, secret := range []string{"static-password", "fake-token", "db.example.com:5432", "db-user", "host=db.example.com port=5432 user=db-user password=static-password dbname=trustgate sslmode=require"} {
				require.NotContains(t, err.Error(), secret)
			}
		})
	}
}
func mustPoolConfig(t *testing.T) *pgxpool.Config {
	t.Helper()
	config, err := pgxpool.ParseConfig("host=db.example.com port=5432 user=db-user password=static-password dbname=trustgate sslmode=require")
	require.NoError(t, err)
	return config
}
