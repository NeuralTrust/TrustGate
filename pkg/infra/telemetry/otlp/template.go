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

package otlp

import (
	"context"
	"log/slog"

	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	infratelemetry "github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry"
)

var _ infratelemetry.ExporterTemplate = (*Template)(nil)

// Template builds otlp.Exporter instances from per-gateway settings, falling
// back to process-level OTEL_EXPORTER_OTLP_* defaults.
type Template struct {
	logger *slog.Logger
	envCfg config.OTLPConfig
}

// NewTemplate returns an OTLP ExporterTemplate bound to the given logger and
// process-level OTEL_EXPORTER_OTLP_* defaults.
func NewTemplate(logger *slog.Logger, envCfg config.OTLPConfig) *Template {
	return &Template{logger: logger, envCfg: envCfg}
}

func (t *Template) Name() string {
	return ExporterName
}

// ValidateConfig performs structural validation only; it never connects to the
// Collector.
func (t *Template) ValidateConfig(settings map[string]interface{}) error {
	s, err := parseSettings(settings, t.envCfg)
	if err != nil {
		return err
	}
	return s.validate()
}

// WithSettings validates the settings then builds a dedicated provider and
// exporter. The OTLP client connects lazily, so an unreachable Collector does
// not fail construction.
func (t *Template) WithSettings(settings map[string]interface{}) (appmetrics.Exporter, error) {
	s, err := parseSettings(settings, t.envCfg)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	provider, err := newLoggerProvider(context.Background(), s)
	if err != nil {
		return nil, err
	}
	return newExporterWithProvider(provider, t.logger, s.MaxBodyBytes, s.Timeout), nil
}
