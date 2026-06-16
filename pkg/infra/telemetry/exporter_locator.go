package telemetry

import (
	"fmt"

	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	telemetrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
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
	template, ok := l.templates[cfg.Name]
	if !ok {
		return nil, fmt.Errorf("unknown exporter %q", cfg.Name)
	}
	if err := template.ValidateConfig(cfg.Settings); err != nil {
		return nil, fmt.Errorf("exporter %q: %w", cfg.Name, err)
	}
	return template.WithSettings(cfg.Settings)
}

func (l *ExporterLocator) Validate(cfg telemetrydomain.ExporterConfig) error {
	template, ok := l.templates[cfg.Name]
	if !ok {
		return fmt.Errorf("unknown exporter %q", cfg.Name)
	}
	if err := template.ValidateConfig(cfg.Settings); err != nil {
		return fmt.Errorf("exporter %q: %w", cfg.Name, err)
	}
	return nil
}
