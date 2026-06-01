package modules

import (
	"log/slog"

	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	apptelemetry "github.com/NeuralTrust/AgentGateway/pkg/app/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domaintelemetry "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry/kafka"
	"go.uber.org/dig"
)

// Telemetry wires the exporter locator (Kafka only for now), the exporters
// builder used for per-gateway exporters, the default exporters built from
// env config, and the metrics worker.
func Telemetry(c *container.Container) error {
	if err := c.Provide(func(logger *slog.Logger, cfg *config.Config) *apptelemetry.ExporterLocator {
		return apptelemetry.NewExporterLocator(
			apptelemetry.WithExporter(kafka.ExporterName, kafka.NewKafkaExporter(logger, cfg.Kafka)),
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(apptelemetry.NewExportersBuilder); err != nil {
		return err
	}
	if err := c.Provide(buildDefaultExporters); err != nil {
		return err
	}
	return c.Provide(appmetrics.NewWorker)
}

// buildDefaultExporters constructs the process-wide default exporters from env
// config. When telemetry is disabled or an exporter cannot be initialized, it
// returns no exporters so request forwarding is never blocked.
func buildDefaultExporters(
	logger *slog.Logger,
	cfg *config.Config,
	locator *apptelemetry.ExporterLocator,
) []apptelemetry.Exporter {
	if !cfg.Telemetry.Enabled {
		return nil
	}
	exporter, err := locator.GetExporter(domaintelemetry.ExporterConfig{
		Name:     kafka.ExporterName,
		Settings: map[string]interface{}{"topic": cfg.Telemetry.KafkaTopic},
	})
	if err != nil {
		logger.Warn("failed to build default kafka exporter, telemetry disabled",
			slog.String("error", err.Error()))
		return nil
	}
	logger.Info("default kafka telemetry exporter initialized",
		slog.String("topic", cfg.Telemetry.KafkaTopic))
	return []apptelemetry.Exporter{exporter}
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
