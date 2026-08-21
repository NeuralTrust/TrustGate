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
	"strings"

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
	return parseDocument(data, fmt.Sprintf("file %q", path))
}

func LoadDefaults(path, metadataYAML, rawYAML string) ([]telemetrydomain.ExporterConfig, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		configs, err := Load(path)
		switch {
		case err == nil:
			return configs, nil
		case !errors.Is(err, ErrFileNotFound):
			return nil, err
		}
	}
	return ParseGroups(metadataYAML, rawYAML)
}

func ParseGroups(metadataYAML, rawYAML string) ([]telemetrydomain.ExporterConfig, error) {
	var groups exporterGroups
	if err := unmarshalList(metadataYAML, &groups.Metadata, "TELEMETRY_EXPORTERS_METADATA", metricsschema.Metadata); err != nil {
		return nil, err
	}
	if err := unmarshalList(rawYAML, &groups.Raw, "TELEMETRY_EXPORTERS_RAW", metricsschema.Raw); err != nil {
		return nil, err
	}
	return fromGroups(groups)
}

func parseDocument(data []byte, source string) ([]telemetrydomain.ExporterConfig, error) {
	var spec fileSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing telemetry exporters %s: %w", source, err)
	}
	return fromGroups(spec.Exporters)
}

func unmarshalList(raw string, dest *[]exporterEntry, source string, class metricsschema.DataClass) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if looksLikeExporterDocument(raw) {
		if err := yaml.Unmarshal([]byte(raw), dest); err != nil {
			return fmt.Errorf("parsing %s: %w", source, err)
		}
		return nil
	}
	entries, err := parseTypeTokens(raw, class)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", source, err)
	}
	*dest = entries
	return nil
}

func looksLikeExporterDocument(raw string) bool {
	switch raw[0] {
	case '[', '{', '-':
		return true
	}
	return strings.Contains(raw, ":")
}

func parseTypeTokens(raw string, class metricsschema.DataClass) ([]exporterEntry, error) {
	parts := strings.Split(raw, ",")
	out := make([]exporterEntry, 0, len(parts))
	for _, part := range parts {
		typ := canonicalExporterType(part)
		if typ == "" {
			return nil, fmt.Errorf("empty exporter type")
		}
		out = append(out, exporterEntry{Name: tokenExporterName(class, typ), Type: typ})
	}
	return out, nil
}

func tokenExporterName(class metricsschema.DataClass, typ string) string {
	if class == "" {
		return typ
	}
	return string(class) + "-" + typ
}

func canonicalExporterType(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "otel" {
		return otelExporterType
	}
	return s
}

func fromGroups(groups exporterGroups) ([]telemetrydomain.ExporterConfig, error) {
	configs := make([]telemetrydomain.ExporterConfig, 0, len(groups.Metadata)+len(groups.Raw))
	for _, e := range groups.Metadata {
		cfg := e.toConfig()
		if cfg.EffectiveType() == postgresExporterType {
			return nil, fmt.Errorf("telemetry exporter %q: %q is raw-only and cannot be declared under exporters.metadata", cfg.Name, postgresExporterType)
		}
		cfg.Class = metricsschema.Metadata
		configs = append(configs, cfg)
	}
	for _, e := range groups.Raw {
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
