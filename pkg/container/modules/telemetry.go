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
	"errors"
	"fmt"
	"log/slog"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	infracache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/playground"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/exportersfile"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/kafka"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/otlp"
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
	defaults, err := newDefaultExporters(logger, factory, cfg.Telemetry.ExportersFile)
	if err != nil {
		return nil, err
	}
	return appmetrics.NewPipeline(builder, cache, playgroundStore, logger, defaults...), nil
}

func newDefaultExporters(
	logger *slog.Logger,
	factory appmetrics.ExporterFactory,
	path string,
) ([]appmetrics.Exporter, error) {
	configs, err := exportersfile.Load(path)
	if err != nil {
		if errors.Is(err, exportersfile.ErrFileNotFound) {
			logger.Warn("telemetry exporters file not found; starting with no default exporters",
				slog.String("path", path))
			return nil, nil
		}
		return nil, fmt.Errorf("loading default telemetry exporters: %w", err)
	}
	if len(configs) == 0 {
		logger.Warn("telemetry exporters file declares no exporters; starting with no default exporters",
			slog.String("path", path))
		return nil, nil
	}
	defaults := make([]appmetrics.Exporter, 0, len(configs))
	for _, cfg := range configs {
		if err := factory.Validate(cfg); err != nil {
			return nil, fmt.Errorf("default telemetry exporter %q: %w", cfg.Name, err)
		}
		exporter, err := factory.Build(cfg)
		if err != nil {
			return nil, fmt.Errorf("default telemetry exporter %q: %w", cfg.Name, err)
		}
		logger.Info("default telemetry exporter initialized",
			slog.String("name", cfg.Name),
			slog.String("type", cfg.EffectiveType()))
		defaults = append(defaults, exporter)
	}
	return defaults, nil
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
