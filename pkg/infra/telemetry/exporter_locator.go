package telemetry

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ExporterLocator struct {
	exporters map[string]telemetry.Exporter
}

func NewProviderLocator(providers map[string]telemetry.Exporter) *ExporterLocator {
	return &ExporterLocator{
		exporters: providers,
	}
}

func (p *ExporterLocator) GetExporter(exporter types.Exporter) (telemetry.Exporter, error) {
	base, ok := p.exporters[exporter.Name]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", exporter.Name)
	}
	provider, err := base.WithSettings(exporter.Settings)
	if err != nil {
		return nil, err
	}
	return provider, nil
}
