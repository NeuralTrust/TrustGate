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
	"testing"

	appconfig "github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestNewPoolAuthStrategy(t *testing.T) {
	loadErr := errors.New("load failed")
	tests := []struct {
		name, region     string
		login            appconfig.PostgresLogin
		loadErr, wantErr error
		wantLoads        int
	}{
		{name: "default parity", login: appconfig.PostgresLoginDefault},
		{name: "empty login parity", login: ""},
		{name: "load error", login: "aws", loadErr: loadErr, wantErr: loadErr, wantLoads: 1},
		{name: "empty region", login: "aws", wantErr: errAWSRegionRequired, wantLoads: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loads := 0
			strategy, err := newPoolAuthStrategy(t.Context(), &appconfig.DatabaseConfig{Login: tt.login}, authDependencies{
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
func TestNewPoolAuthStrategyRejectsUnsupportedLogin(t *testing.T) {
	loads := 0
	strategy, err := newPoolAuthStrategy(t.Context(), &appconfig.DatabaseConfig{Login: "gcp"}, authDependencies{
		loadConfig: func(context.Context, ...func(*awsconfig.LoadOptions) error) (aws.Config, error) {
			loads++
			return aws.Config{Region: "eu-west-1"}, nil
		},
	})
	require.ErrorIs(t, err, errUnsupportedDBLogin)
	require.ErrorContains(t, err, "gcp")
	require.Nil(t, strategy)
	require.Zero(t, loads)
}
func mustPoolConfig(t *testing.T) *pgxpool.Config {
	t.Helper()
	config, err := pgxpool.ParseConfig("host=db.example.com port=5432 user=db-user password=static-password dbname=trustgate sslmode=require")
	require.NoError(t, err)
	return config
}
