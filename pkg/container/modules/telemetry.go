// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package modules

import (
	"log/slog"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	infracache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/playground"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/kafka"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/otlp"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"go.uber.org/dig"
)

func Telemetry(c *container.Container) error {
	// NewBuilder depends on a segregated decoder view; the concrete adapter
	// registry satisfies it, but dig resolves by exact type so we bind it here.
	if err := c.Provide(func(registry *adapter.Registry, pricing appcatalog.PricingResolver) *appmetrics.Builder {
		return appmetrics.NewBuilder(registry, pricing)
	}); err != nil {
		return err
	}
	if err := c.Provide(newExporterFactory); err != nil {
		return err
	}
	if err := c.Provide(appmetrics.NewExporterCache); err != nil {
		return err
	}
	if err := c.Provide(newPlaygroundTraceStore); err != nil {
		return err
	}
	if err := c.Provide(buildPipeline); err != nil {
		return err
	}
	return c.Provide(appmetrics.NewWorker)
}

// newPlaygroundTraceStore uses the raw Redis client (not the in-process TTL
// cache) so traces get a real Redis TTL and are visible across the proxy and
// admin planes.
func newPlaygroundTraceStore(
	cc infracache.Client,
	cfg *config.Config,
	logger *slog.Logger,
) *playground.Store {
	return playground.NewStore(cc.RedisClient(), cfg.Playground, logger)
}

func newExporterFactory(logger *slog.Logger, cfg *config.Config) appmetrics.ExporterFactory {
	return infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter(kafka.ExporterName, kafka.NewKafkaTemplate(logger, cfg.Kafka)),
		infratelemetry.WithExporter(otlp.ExporterName, otlp.NewTemplate(logger, cfg.Telemetry.OTLP)),
	)
}

func buildPipeline(
	logger *slog.Logger,
	cfg *config.Config,
	builder *appmetrics.Builder,
	factory appmetrics.ExporterFactory,
	cache *appmetrics.ExporterCache,
	playgroundStore *playground.Store,
) (*appmetrics.Pipeline, error) {
	if !cfg.Telemetry.Enabled {
		if cfg.Playground.TraceStoreEnabled {
			logger.Warn("playground trace store enabled but telemetry is disabled; no traces will be stored")
		}
		return nil, nil
	}
	var defaults []appmetrics.Exporter
	exporter, err := factory.Build(telemetrydomain.ExporterConfig{
		Name:     kafka.ExporterName,
		Class:    metrics.Raw,
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
	return appmetrics.NewPipeline(builder, cache, playgroundStore, logger, defaults...), nil
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
	p.Logger.Info(bootlog.MetricsWorkerStarted, slog.Int("workers", n))
}
