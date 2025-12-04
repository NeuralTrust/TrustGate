package telemetry

import (
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	factory "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ExportersBuilder interface {
	Build(configs []types.Exporter) ([]domain.Exporter, error)
}

type exportersBuilder struct {
	locator *factory.ExporterLocator
}

func NewTelemetryExportersBuilder(locator *factory.ExporterLocator) ExportersBuilder {
	return &exportersBuilder{
		locator: locator,
	}
}

func (v *exportersBuilder) Build(configs []types.Exporter) ([]domain.Exporter, error) {
	var providers []domain.Exporter

	for _, config := range configs {
		telemetryProvider, err := v.locator.GetExporter(config)
		if err != nil {
			return nil, err
		}
		providers = append(providers, telemetryProvider)
	}
	return providers, nil
}
