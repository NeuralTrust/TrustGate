package modules

import (
	"log/slog"

	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/telemetry/kafka"
	"go.uber.org/dig"
)

// Telemetry wires the consolidated metrics pipeline (event builder + Kafka
// exporter) and the metrics worker.
func Telemetry(c *container.Container) error {
	if err := c.Provide(appmetrics.NewBuilder); err != nil {
		return err
	}
	if err := c.Provide(buildPipeline); err != nil {
		return err
	}
	return c.Provide(appmetrics.NewWorker)
}

// buildPipeline constructs the metrics pipeline (builder + Kafka exporter on the
// telemetry topic) when telemetry is enabled. When disabled, or when the
// exporter cannot be initialized, it returns a nil pipeline so the worker
// silently skips publishing.
func buildPipeline(
	logger *slog.Logger,
	cfg *config.Config,
	builder *appmetrics.Builder,
) (*appmetrics.Pipeline, error) {
	if !cfg.Telemetry.Enabled {
		return nil, nil
	}
	exporter, err := kafka.NewKafkaExporter(logger, cfg.Kafka, cfg.Telemetry.KafkaTopic)
	if err != nil {
		logger.Warn("failed to build kafka exporter, telemetry disabled",
			slog.String("error", err.Error()))
		return nil, nil
	}
	logger.Info("metrics telemetry exporter initialized",
		slog.String("topic", cfg.Telemetry.KafkaTopic))
	return appmetrics.NewPipeline(builder, exporter, logger), nil
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
