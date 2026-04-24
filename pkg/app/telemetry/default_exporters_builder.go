package telemetry

import (
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	factory "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/trustlens"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
)

type DefaultExportersBuilder struct {
	logger  *logrus.Logger
	locator *factory.ExporterLocator
}

func NewDefaultExportersBuilder(
	logger *logrus.Logger,
	locator *factory.ExporterLocator,
) *DefaultExportersBuilder {
	return &DefaultExportersBuilder{
		logger:  logger,
		locator: locator,
	}
}

func (b *DefaultExportersBuilder) Build() []domain.Exporter {
	exporterConfigs := []types.ExporterDTO{
		{
			Name:     trustlens.ExporterName,
			Settings: map[string]interface{}{"topic": trustlens.DefaultTopic},
		},
	}

	var exporters []domain.Exporter
	for _, dto := range exporterConfigs {
		exp, err := b.locator.GetExporter(dto)
		if err != nil {
			b.logger.WithError(err).WithField("exporter", dto.Name).
				Warn("failed to build default exporter, skipping")
			continue
		}
		b.logger.WithField("exporter", dto.Name).Info("default exporter initialized")
		exporters = append(exporters, exp)
	}

	return exporters
}
