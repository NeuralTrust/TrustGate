package telemetry

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
)

type Exporter interface {
	Name() string
	ValidateConfig() error
	Handle(ctx context.Context, evt *metric_events.Event) error
	WithSettings(settings map[string]interface{}) (Exporter, error)
	Close()
}
