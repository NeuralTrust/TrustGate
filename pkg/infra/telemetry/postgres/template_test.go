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

package postgres

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestFallbackPoolConfig_UsesServiceDatabaseConfig(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")

	dbCfg := &config.DatabaseConfig{
		Login:    "default",
		Host:     "db.example.com",
		Port:     5432,
		User:     "agentgateway",
		Password: "s3cret",
		Name:     "agentgateway",
		SSLMode:  "require",
		MaxConns: 20,
		MinConns: 5,
	}
	tpl := NewTemplate(testLogger(), dbCfg)

	conf, err := tpl.fallbackPoolConfig(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "db.example.com", conf.ConnConfig.Host)
	assert.Equal(t, "agentgateway", conf.ConnConfig.User)
	assert.Equal(t, "agentgateway", conf.ConnConfig.Database)
	assert.Equal(t, "s3cret", conf.ConnConfig.Password)
	// Telemetry sink must not inherit the app pool budget.
	assert.Equal(t, telemetryMaxConns, conf.MaxConns)
	assert.Equal(t, telemetryMinConns, conf.MinConns)
}

func TestFallbackPoolConfig_IAMAuthStrategy(t *testing.T) {
	t.Setenv("AWS_REGION", "eu-west-1")

	dbCfg := &config.DatabaseConfig{
		Login:    "aws",
		Host:     "db.example.com",
		Port:     5432,
		User:     "agentgateway_iam",
		Password: "",
		Name:     "agentgateway",
		SSLMode:  "require",
	}
	tpl := NewTemplate(testLogger(), dbCfg)

	conf, err := tpl.fallbackPoolConfig(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "agentgateway", conf.ConnConfig.Database)
	assert.Empty(t, conf.ConnConfig.Password)
	assert.NotNil(t, conf.BeforeConnect)
}

func TestFallbackPoolConfig_RequiresDatabaseConfig(t *testing.T) {
	tpl := NewTemplate(testLogger(), nil)
	_, err := tpl.fallbackPoolConfig(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DatabaseConfig")
}

func TestValidateConfig_AllowsEmptySettings(t *testing.T) {
	tpl := NewTemplate(testLogger(), &config.DatabaseConfig{Host: "localhost"})
	require.NoError(t, tpl.ValidateConfig(nil))
	require.NoError(t, tpl.ValidateConfig(map[string]interface{}{}))
}
