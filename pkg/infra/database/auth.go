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
	"net"
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	errAWSRegionRequired  = errors.New("aws region is required")
	errUnsupportedDBLogin = errors.New("unsupported database login")
)

type poolAuthStrategy func(*pgxpool.Config)
type tokenFetcher func(context.Context, *pgx.ConnConfig) (string, error)
type authStrategyFactory func(context.Context, *config.DatabaseConfig, authDependencies) (poolAuthStrategy, error)
type awsConfigLoader func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error)
type authTokenBuilder func(context.Context, string, string, string, aws.CredentialsProvider) (string, error)
type authDependencies struct {
	loadConfig          awsConfigLoader
	buildToken          authTokenBuilder
	loadAzureCredential azureCredentialLoader
}

var authStrategyFactories = map[config.PostgresLogin]authStrategyFactory{
	config.PostgresLoginAWS:   newAWSAuthStrategy,
	config.PostgresLoginAzure: newAzureAuthStrategy,
}

func defaultAuthDependencies() authDependencies {
	return authDependencies{loadConfig: awsconfig.LoadDefaultConfig, buildToken: buildAuthToken, loadAzureCredential: defaultAzureCredential}
}
func buildAuthToken(ctx context.Context, endpoint, region, user string, credentials aws.CredentialsProvider) (string, error) {
	return rdsauth.BuildAuthToken(ctx, endpoint, region, user, credentials)
}
func newPoolAuthStrategy(ctx context.Context, cfg *config.DatabaseConfig, dependencies authDependencies) (poolAuthStrategy, error) {
	if !cfg.Login.UsesTokenAuth() {
		return func(*pgxpool.Config) {}, nil
	}
	factory, supported := authStrategyFactories[cfg.Login]
	if !supported {
		return nil, fmt.Errorf("%w %q", errUnsupportedDBLogin, cfg.Login)
	}
	return factory(ctx, cfg, dependencies)
}
func newAWSAuthStrategy(ctx context.Context, _ *config.DatabaseConfig, dependencies authDependencies) (poolAuthStrategy, error) {
	awsConfig, err := dependencies.loadConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load aws database authentication config: %w", err)
	}
	region := awsConfig.Region
	if region == "" {
		return nil, errAWSRegionRequired
	}
	credentials := awsConfig.Credentials
	buildToken := dependencies.buildToken
	return newTokenAuthStrategy(func(ctx context.Context, connConfig *pgx.ConnConfig) (string, error) {
		endpoint := net.JoinHostPort(connConfig.Host, strconv.Itoa(int(connConfig.Port)))
		return buildToken(ctx, endpoint, region, connConfig.User, credentials)
	}), nil
}
func newTokenAuthStrategy(fetchToken tokenFetcher) poolAuthStrategy {
	return func(poolConfig *pgxpool.Config) {
		previousHook := poolConfig.BeforeConnect
		poolConfig.ConnConfig.Password = ""
		poolConfig.BeforeConnect = func(ctx context.Context, connConfig *pgx.ConnConfig) error {
			if previousHook != nil {
				if err := previousHook(ctx, connConfig); err != nil {
					return fmt.Errorf("run database connection hook: %w", err)
				}
			}
			if connConfig.ConnectTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, connConfig.ConnectTimeout)
				defer cancel()
			}
			token, err := fetchToken(ctx, connConfig)
			if err != nil {
				return fmt.Errorf("build database authentication token: %w", err)
			}
			connConfig.Password = token
			return nil
		}
	}
}
