package telemetry

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ExporterLocator struct {
	exporters map[string]telemetry.Exporter
}

func NewProviderLocator(opts ...ExporterLocatorOption) *ExporterLocator {
	el := &ExporterLocator{
		exporters: make(map[string]telemetry.Exporter),
	}
	for _, opt := range opts {
		opt(el)
	}
	return el
}

func (p *ExporterLocator) GetExporter(exporter types.ExporterDTO) (telemetry.Exporter, error) {
	base, ok := p.exporters[exporter.Name]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", exporter.Name)
	}
	if err := base.ValidateConfig(exporter.Settings); err != nil {
		return nil, err
	}
	provider, err := base.WithSettings(exporter.Settings)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *ExporterLocator) ValidateExporter(exporter types.ExporterDTO) error {
	base, ok := p.exporters[exporter.Name]
	if !ok {
		return fmt.Errorf("unknown provider: %s", exporter.Name)
	}
	return base.ValidateConfig(exporter.Settings)
}
