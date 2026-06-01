package telemetry

import (
	"fmt"

	domaintelemetry "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
)

// ExporterLocator resolves configured exporters by name and returns a fresh,
// settings-bound instance for each request configuration.
type ExporterLocator struct {
	exporters map[string]Exporter
}

type ExporterLocatorOption func(*ExporterLocator)

// WithExporter registers an exporter under the given name.
func WithExporter(name string, exporter Exporter) ExporterLocatorOption {
	return func(el *ExporterLocator) {
		if el.exporters == nil {
			el.exporters = make(map[string]Exporter)
		}
		el.exporters[name] = exporter
	}
}

func NewExporterLocator(opts ...ExporterLocatorOption) *ExporterLocator {
	el := &ExporterLocator{
		exporters: make(map[string]Exporter),
	}
	for _, opt := range opts {
		opt(el)
	}
	return el
}

func (p *ExporterLocator) GetExporter(cfg domaintelemetry.ExporterConfig) (Exporter, error) {
	base, ok := p.exporters[cfg.Name]
	if !ok {
		return nil, fmt.Errorf("unknown exporter: %s", cfg.Name)
	}
	if err := base.ValidateConfig(cfg.Settings); err != nil {
		return nil, err
	}
	return base.WithSettings(cfg.Settings)
}

func (p *ExporterLocator) ValidateExporter(cfg domaintelemetry.ExporterConfig) error {
	base, ok := p.exporters[cfg.Name]
	if !ok {
		return fmt.Errorf("unknown exporter: %s", cfg.Name)
	}
	return base.ValidateConfig(cfg.Settings)
}

//go:generate mockery --name=ExportersBuilder --dir=. --output=./mocks --filename=exporters_builder_mock.go --case=underscore --with-expecter
type ExportersBuilder interface {
	Build(configs []domaintelemetry.ExporterConfig) ([]Exporter, error)
}

var _ ExportersBuilder = (*exportersBuilder)(nil)

type exportersBuilder struct {
	locator *ExporterLocator
}

func NewExportersBuilder(locator *ExporterLocator) ExportersBuilder {
	return &exportersBuilder{locator: locator}
}

func (v *exportersBuilder) Build(configs []domaintelemetry.ExporterConfig) ([]Exporter, error) {
	var exporters []Exporter
	for _, cfg := range configs {
		exporter, err := v.locator.GetExporter(cfg)
		if err != nil {
			// Close the exporters built so far so their producers/goroutines do
			// not leak when a later config in the batch fails to build.
			for _, built := range exporters {
				built.Close()
			}
			return nil, err
		}
		exporters = append(exporters, exporter)
	}
	return exporters, nil
}
