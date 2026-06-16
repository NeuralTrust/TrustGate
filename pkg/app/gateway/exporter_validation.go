package gateway

import (
	"fmt"

	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
)

func validateExporters(factory appmetrics.ExporterFactory, tel *telemetry.Telemetry) error {
	if tel == nil || len(tel.Exporters) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tel.Exporters))
	for _, exporter := range tel.Exporters {
		if _, dup := seen[exporter.Name]; dup {
			return fmt.Errorf("duplicate telemetry exporter %q: %w", exporter.Name, commonerrors.ErrValidation)
		}
		seen[exporter.Name] = struct{}{}
		if factory == nil {
			continue
		}
		if err := factory.Validate(exporter); err != nil {
			return fmt.Errorf("invalid telemetry exporter: %v: %w", err, commonerrors.ErrValidation)
		}
	}
	return nil
}
