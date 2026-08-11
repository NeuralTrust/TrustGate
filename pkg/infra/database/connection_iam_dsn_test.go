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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/require"
)

// Empty password= in a keyword DSN makes pgx swallow dbname as the password.
// IAM auth must omit the password key entirely so Database stays set.
func TestBuildPoolConfig_IAMOmitsEmptyPassword(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	cfg := &config.DatabaseConfig{
		Login:    "aws",
		Host:     "db.example.com",
		Port:     5432,
		User:     "agentgateway_iam",
		Password: "",
		Name:     "agentgateway",
		SSLMode:  "require",
		MaxConns: 1,
		MinConns: 0,
	}
	poolCfg, err := buildPoolConfig(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "agentgateway", poolCfg.ConnConfig.Database)
	require.Equal(t, "agentgateway_iam", poolCfg.ConnConfig.User)
	require.Empty(t, poolCfg.ConnConfig.Password)
}
