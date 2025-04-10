package telemetry

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

type Exporter interface {
	Name() string
	ValidateConfig() error
	Handle(ctx context.Context, evt *metrics.Event) error
	WithSettings(settings map[string]interface{}) (Exporter, error)
}
