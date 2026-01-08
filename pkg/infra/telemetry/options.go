package telemetry

import "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"

// ExporterLocatorOption is a function that configures an ExporterLocator
type ExporterLocatorOption func(*ExporterLocator)

// WithExporter registers an exporter with the given name
func WithExporter(name string, exporter telemetry.Exporter) ExporterLocatorOption {
	return func(el *ExporterLocator) {
		if el.exporters == nil {
			el.exporters = make(map[string]telemetry.Exporter)
		}
		el.exporters[name] = exporter
	}
}


