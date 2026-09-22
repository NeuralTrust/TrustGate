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
)

var errAWSRegionRequired = errors.New("aws region is required")

type awsConfigLoader func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error)
type authTokenBuilder func(context.Context, string, string, string, aws.CredentialsProvider) (string, error)

func defaultAWSConfigLoader() awsConfigLoader {
	return awsconfig.LoadDefaultConfig
}
func buildAuthToken(ctx context.Context, endpoint, region, user string, credentials aws.CredentialsProvider) (string, error) {
	return rdsauth.BuildAuthToken(ctx, endpoint, region, user, credentials)
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
