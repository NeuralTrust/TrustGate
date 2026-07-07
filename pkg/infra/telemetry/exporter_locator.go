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

package telemetry

import (
	"fmt"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
)

type ExporterTemplate interface {
	Name() string
	ValidateConfig(settings map[string]interface{}) error
	WithSettings(settings map[string]interface{}) (appmetrics.Exporter, error)
}

type ExporterLocator struct {
	templates map[string]ExporterTemplate
}

type ExporterLocatorOption func(*ExporterLocator)

func WithExporter(name string, template ExporterTemplate) ExporterLocatorOption {
	return func(l *ExporterLocator) {
		l.templates[name] = template
	}
}

func NewExporterLocator(opts ...ExporterLocatorOption) *ExporterLocator {
	locator := &ExporterLocator{templates: make(map[string]ExporterTemplate)}
	for _, opt := range opts {
		opt(locator)
	}
	return locator
}

func (l *ExporterLocator) Build(cfg telemetrydomain.ExporterConfig) (appmetrics.Exporter, error) {
	if err := cfg.ValidateClass(); err != nil {
		return nil, err
	}
	template, ok := l.templates[cfg.EffectiveType()]
	if !ok {
		return nil, fmt.Errorf("unknown exporter %q", cfg.Name)
	}
	if err := template.ValidateConfig(cfg.Settings); err != nil {
		return nil, fmt.Errorf("exporter %q: %w", cfg.Name, err)
	}
	exporter, err := template.WithSettings(cfg.Settings)
	if err != nil {
		return nil, err
	}
	return withDataClass(exporter, cfg.EffectiveClass()), nil
}

func (l *ExporterLocator) Validate(cfg telemetrydomain.ExporterConfig) error {
	if err := cfg.ValidateClass(); err != nil {
		return err
	}
	template, ok := l.templates[cfg.EffectiveType()]
	if !ok {
		return fmt.Errorf("unknown exporter %q", cfg.Name)
	}
	if err := template.ValidateConfig(cfg.Settings); err != nil {
		return fmt.Errorf("exporter %q: %w", cfg.Name, err)
	}
	return nil
}

type classSetter interface {
	SetDataClass(metrics.DataClass)
}

type classOverride struct {
	appmetrics.Exporter
	class metrics.DataClass
}

func (c classOverride) DataClass() metrics.DataClass { return c.class }

func withDataClass(exporter appmetrics.Exporter, class metrics.DataClass) appmetrics.Exporter {
	if exporter == nil {
		return exporter
	}
	if setter, ok := exporter.(classSetter); ok {
		setter.SetDataClass(class)
		return exporter
	}
	if exporter.DataClass() == class {
		return exporter
	}
	return classOverride{Exporter: exporter, class: class}
}
