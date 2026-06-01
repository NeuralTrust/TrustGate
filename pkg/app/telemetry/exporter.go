package telemetry

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/metric_events"
)

//go:generate mockery --name=Exporter --dir=. --output=./mocks --filename=exporter_mock.go --case=underscore --with-expecter
type Exporter interface {
	Name() string
	ValidateConfig(settings map[string]interface{}) error
	WithSettings(settings map[string]interface{}) (Exporter, error)
	Handle(ctx context.Context, evt metric_events.Event) error
	Close()
}
