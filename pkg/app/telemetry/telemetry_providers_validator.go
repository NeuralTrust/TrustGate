package telemetry

import (
	factory "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ExportersValidator interface {
	Validate(configs []types.Exporter) error
}

type exportersValidator struct {
	locator *factory.ExporterLocator
}

func NewTelemetryExportersValidator(locator *factory.ExporterLocator) ExportersValidator {
	return &exportersValidator{
		locator: locator,
	}
}

func (v *exportersValidator) Validate(configs []types.Exporter) error {
	for _, config := range configs {
		err := v.locator.ValidateExporter(config)
		if err != nil {
			return err
		}
	}
	return nil
}
