package modules

import (
	"log/slog"

	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	telemetrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	infratelemetry "github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry/kafka"
	"go.uber.org/dig"
)

func Telemetry(c *container.Container) error {
	if err := c.Provide(appmetrics.NewBuilder); err != nil {
		return err
	}
	if err := c.Provide(newExporterFactory); err != nil {
		return err
	}
	if err := c.Provide(appmetrics.NewExporterCache); err != nil {
		return err
	}
	if err := c.Provide(buildPipeline); err != nil {
		return err
	}
	return c.Provide(appmetrics.NewWorker)
}

func newExporterFactory(logger *slog.Logger, cfg *config.Config) appmetrics.ExporterFactory {
	return infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter(kafka.ExporterName, kafka.NewKafkaTemplate(logger, cfg.Kafka)),
	)
}

func buildPipeline(
	logger *slog.Logger,
	cfg *config.Config,
	builder *appmetrics.Builder,
	factory appmetrics.ExporterFactory,
	cache *appmetrics.ExporterCache,
) (*appmetrics.Pipeline, error) {
	if !cfg.Telemetry.Enabled {
		return nil, nil
	}
	var defaults []appmetrics.Exporter
	exporter, err := factory.Build(telemetrydomain.ExporterConfig{
		Name:     kafka.ExporterName,
		Settings: map[string]interface{}{"topic": cfg.Telemetry.KafkaTopic},
	})
	if err != nil {
		logger.Warn("failed to build default kafka exporter, default telemetry disabled",
			slog.String("error", err.Error()))
	} else {
		logger.Info("metrics telemetry exporter initialized",
			slog.String("topic", cfg.Telemetry.KafkaTopic))
		defaults = append(defaults, exporter)
	}
	return appmetrics.NewPipeline(builder, cache, logger, defaults...), nil
}

// MetricsWorkerParams collects everything StartMetricsWorker needs.
type MetricsWorkerParams struct {
	dig.In
	Logger *slog.Logger
	Cfg    *config.Config
	Worker appmetrics.Worker
}

// StartMetricsWorker starts the background metrics worker goroutines. It is
// meant to be invoked once on the proxy plane at boot.
func StartMetricsWorker(p MetricsWorkerParams) {
	n := p.Cfg.Metrics.WorkerCount
	if n <= 0 {
		n = 1
	}
	p.Worker.StartWorkers(n)
	p.Logger.Info("metrics worker started", slog.Int("workers", n))
}
