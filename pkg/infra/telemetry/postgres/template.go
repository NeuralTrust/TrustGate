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
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ infratelemetry.ExporterTemplate = (*Template)(nil)

// buildTimeout bounds pool creation plus first-build migrations so an
// unreachable sensible DB cannot block the pipeline's ExporterCache indefinitely.
const buildTimeout = 30 * time.Second

// Template builds postgres.Exporter instances and runs the sensible-store
// migrations the first time the exporter is built.
type Template struct {
	logger *slog.Logger
}

// NewTemplate returns a postgres ExporterTemplate bound to the given logger.
func NewTemplate(logger *slog.Logger) *Template {
	return &Template{logger: logger}
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
func (t *Template) WithSettings(settings map[string]interface{}) (appmetrics.Exporter, error) {
	s, err := parseSettings(settings)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	dsn, err := s.resolveDSN()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	if err := runMigrations(ctx, pool, t.logger); err != nil {
		pool.Close()
		return nil, err
	}
	return newExporter(pool, s.Table, t.logger), nil
}
