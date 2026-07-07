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

package exportersfile

import (
	"errors"
	"fmt"
	"os"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
	"gopkg.in/yaml.v3"
)

var ErrFileNotFound = errors.New("telemetry exporters file not found")

const (
	postgresExporterType = "postgres"
	otelExporterType     = "otlp"
)

type fileSpec struct {
	Exporters exporterGroups `yaml:"exporters"`
}

type exporterGroups struct {
	Metadata []exporterEntry `yaml:"metadata"`
	Raw      []exporterEntry `yaml:"raw"`
}

type exporterEntry struct {
	Name     string                 `yaml:"name"`
	Type     string                 `yaml:"type"`
	Settings map[string]interface{} `yaml:"settings"`
}

func Load(path string) ([]telemetrydomain.ExporterConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%q: %w", path, ErrFileNotFound)
		}
		return nil, fmt.Errorf("reading telemetry exporters file %q: %w", path, err)
	}
	var spec fileSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing telemetry exporters file %q: %w", path, err)
	}

	configs := make([]telemetrydomain.ExporterConfig, 0, len(spec.Exporters.Metadata)+len(spec.Exporters.Raw))
	for _, e := range spec.Exporters.Metadata {
		cfg := e.toConfig()
		if cfg.EffectiveType() == postgresExporterType {
			return nil, fmt.Errorf("telemetry exporter %q: %q is raw-only and cannot be declared under exporters.metadata", cfg.Name, postgresExporterType)
		}
		cfg.Class = metricsschema.Metadata
		configs = append(configs, cfg)
	}
	for _, e := range spec.Exporters.Raw {
		cfg := e.toConfig()
		switch cfg.EffectiveType() {
		case postgresExporterType, otelExporterType:
		default:
			return nil, fmt.Errorf("telemetry exporter %q: exporters.raw only accepts %q or %q, got %q", cfg.Name, postgresExporterType, otelExporterType, cfg.EffectiveType())
		}
		cfg.Class = metricsschema.Raw
		configs = append(configs, cfg)
	}
	return configs, nil
}

func (e exporterEntry) toConfig() telemetrydomain.ExporterConfig {
	return telemetrydomain.ExporterConfig{
		Name:     e.Name,
		Type:     e.Type,
		Settings: e.Settings,
	}
}
