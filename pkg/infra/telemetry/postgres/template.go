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
	"fmt"
	"log/slog"
	"time"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ infratelemetry.ExporterTemplate = (*Template)(nil)

// buildTimeout bounds pool creation plus first-build migrations so an
// unreachable sensible DB cannot block the pipeline's ExporterCache indefinitely.
const buildTimeout = 30 * time.Second

// Telemetry sinks share the service DatabaseConfig for host/auth but must not
// inherit the app pool's connection budget — that would double pressure on
// Postgres. Keep the sink pool small.
const (
	telemetryMaxConns = int32(2)
	telemetryMinConns = int32(0)
)

// Template builds postgres.Exporter instances and runs the sensible-store
// migrations the first time the exporter is built.
type Template struct {
	logger *slog.Logger
	dbCfg  *config.DatabaseConfig
}

// NewTemplate returns a postgres ExporterTemplate bound to the given logger
// and the service's DatabaseConfig (used when settings name neither dsn nor
// dsn_env).
func NewTemplate(logger *slog.Logger, dbCfg *config.DatabaseConfig) *Template {
	return &Template{logger: logger, dbCfg: dbCfg}
}

func (t *Template) Name() string {
	return ExporterName
}

// ValidateConfig performs structural validation only; it never opens a
// connection or resolves the DSN env var.
func (t *Template) ValidateConfig(settings map[string]interface{}) error {
	s, err := parseSettings(settings)
	if err != nil {
		return err
	}
	return s.validate()
}

// WithSettings validates the settings, opens a dedicated pool, and applies the
// schema migrations (advisory-locked) before returning the exporter.
//
// Connection precedence: literal dsn > dsn_env > service DatabaseConfig.
func (t *Template) WithSettings(settings map[string]interface{}) (appmetrics.Exporter, error) {
	s, err := parseSettings(settings)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	pool, err := t.openPool(ctx, s)
	if err != nil {
		return nil, err
	}
	if err := runMigrations(ctx, pool, t.logger); err != nil {
		pool.Close()
		return nil, err
	}
	return newExporter(pool, s.Table, t.logger), nil
}

func (t *Template) openPool(ctx context.Context, s Settings) (*pgxpool.Pool, error) {
	if s.hasDSNSource() {
		dsn, err := s.resolveDSN()
		if err != nil {
			return nil, err
		}
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return nil, fmt.Errorf("postgres: open pool: %w", err)
		}
		return pool, nil
	}
	conf, err := t.fallbackPoolConfig(ctx)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool from service database settings: %w", err)
	}
	return pool, nil
}

// fallbackPoolConfig builds a pool config from the service DatabaseConfig,
// capped to the telemetry sink's connection budget. Exported only for tests
// via the package-private method.
func (t *Template) fallbackPoolConfig(ctx context.Context) (*pgxpool.Config, error) {
	if t.dbCfg == nil {
		return nil, fmt.Errorf("postgres: no dsn/dsn_env configured and no service DatabaseConfig available")
	}
	conf, err := database.NewPoolConfig(ctx, t.dbCfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: build pool config from service database settings: %w", err)
	}
	conf.MaxConns = telemetryMaxConns
	conf.MinConns = telemetryMinConns
	return conf, nil
}
