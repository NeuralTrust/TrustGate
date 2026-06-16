package metrics

import telemetrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"

//go:generate mockery --name=ExporterFactory --dir=. --output=./mocks --filename=exporter_factory_mock.go --case=underscore --with-expecter
type ExporterFactory interface {
	Build(cfg telemetrydomain.ExporterConfig) (Exporter, error)
	Validate(cfg telemetrydomain.ExporterConfig) error
}
