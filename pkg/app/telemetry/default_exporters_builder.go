package telemetry

import (
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	factory "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/trustlens"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
)

type DefaultExportersBuilder struct {
	logger  *logrus.Logger
	locator *factory.ExporterLocator
	cfg     config.KafkaConfig
}

func NewDefaultExportersBuilder(
	logger *logrus.Logger,
	locator *factory.ExporterLocator,
	cfg config.KafkaConfig,
) *DefaultExportersBuilder {
	return &DefaultExportersBuilder{
		logger:  logger,
		locator: locator,
		cfg:     cfg,
	}
}

func (b *DefaultExportersBuilder) Build() []domain.Exporter {
	if b.cfg.Host == "" {
		b.logger.Info("KAFKA_HOST not set, skipping default exporters")
		return nil
	}

	settings := map[string]interface{}{
		"host": b.cfg.Host,
		"port": b.cfg.Port,
	}

	exporterConfigs := []types.ExporterDTO{
		{
			Name: trustlens.ExporterName,
			Settings: mergeMaps(settings, map[string]interface{}{
				"topic": trustlens.DefaultTopic,
			}),
		},
	}

	var exporters []domain.Exporter
	for _, dto := range exporterConfigs {
		exp, err := b.locator.GetExporter(dto)
		if err != nil {
			b.logger.WithError(err).WithField("exporter", dto.Name).
				Error("failed to build default exporter, skipping")
			continue
		}
		b.logger.WithFields(logrus.Fields{
			"exporter": dto.Name,
			"host":     b.cfg.Host,
			"port":     b.cfg.Port,
		}).Info("default exporter initialized")
		exporters = append(exporters, exp)
	}

	return exporters
}

func mergeMaps(base, override map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(base)+len(override))
	for k, v := range base {
		result[k] = v
	}
	for k, v := range override {
		result[k] = v
	}
	return result
}
