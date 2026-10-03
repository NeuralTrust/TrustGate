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
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/labelcache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/labelllm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/labelstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"go.uber.org/dig"
)

const (
	labelGroupTimeout    = 5 * time.Second
	labelShutdownTimeout = 5 * time.Second

	labelCacheKeyInfo = "trustgate/traffic-labels-cache"
	labelCacheKeyLen  = 32
)

func TrafficLabels(c *container.Container) error {
	for _, provider := range []any{
		newLabelStream,
		newTrafficLabelsMetrics,
		newLabelClassifier,
		newLabelCache,
		newLabelSink,
		newLabelIntake,
		newLabelWorker,
		newTrafficLabelsMiddleware,
	} {
		if err := c.Provide(provider); err != nil {
			return err
		}
	}
	return nil
}

func newLabelStream(cc cache.Client, cfg *config.Config) *labelstream.Stream {
	return labelstream.New(cc.RedisClient(), labelstream.Config{
		MaxLen:                cfg.TrafficLabels.StreamMaxLen,
		Retention:             cfg.TrafficLabels.StreamRetention,
		GatewayQuotaPerSecond: cfg.TrafficLabels.GatewayQuotaPerSecond,
	})
}

func newTrafficLabelsMetrics(cfg *config.Config, sdk *o11y.SDK, stream *labelstream.Stream) (*o11y.TrafficLabelsMetrics, error) {
	return o11y.NewTrafficLabelsMetrics(cfg, sdk, stream.Stats)
}

func newLabelClassifier(
	registries registrydomain.Repository,
	locator factory.ProviderLocator,
	codec *adapter.Registry,
	cfg *config.Config,
) trafficlabels.Classifier {
	return labelllm.New(registries, locator, codec, labelllm.Config{
		Timeout:   cfg.TrafficLabels.ClassifierTimeout,
		MaxTokens: cfg.TrafficLabels.MaxTokens,
	})
}

// The unused Encrypter forces SERVER_SECRET_KEY to be resolved in prod before it is read.
func newLabelCache(cc cache.Client, cfg *config.Config, _ vaultdomain.Encrypter, logger *slog.Logger) trafficlabels.Cache {
	secret := cfg.Server.SecretKey
	if secret == "" {
		logger.Warn("traffic labels: SERVER_SECRET_KEY is not set, classifications are not cached")
		return nil
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, labelCacheKeyInfo, labelCacheKeyLen)
	if err != nil {
		logger.Warn("traffic labels: cache key not derived, classifications are not cached", slog.String("error", err.Error()))
		return nil
	}
	return labelcache.New(cc.RedisClient(), cfg.TrafficLabels.CacheTTL, key)
}

func newLabelSink(gateways gatewaydomain.Repository, pipeline *appmetrics.Pipeline) trafficlabels.Sink {
	return trafficlabels.NewEventSink(gateways, pipeline)
}

func newLabelIntake(
	logger *slog.Logger,
	registry *adapter.Registry,
	stream *labelstream.Stream,
	metrics *o11y.TrafficLabelsMetrics,
	cfg *config.Config,
) trafficlabels.Intake {
	return trafficlabels.NewIntake(logger, registry, stream, metrics, trafficlabels.IntakeConfig{
		QueueSize:      cfg.TrafficLabels.IntakeQueueSize,
		Workers:        cfg.TrafficLabels.IntakeWorkers,
		EnqueueTimeout: cfg.TrafficLabels.EnqueueTimeout,
		MaxBufferBytes: cfg.TrafficLabels.IntakeMaxBufferBytes,
	})
}

func newLabelWorker(
	logger *slog.Logger,
	stream *labelstream.Stream,
	classifier trafficlabels.Classifier,
	labelCache trafficlabels.Cache,
	sink trafficlabels.Sink,
	metrics *o11y.TrafficLabelsMetrics,
	cfg *config.Config,
) trafficlabels.Worker {
	return trafficlabels.NewWorker(logger, stream, classifier, labelCache, sink, metrics, trafficlabels.WorkerConfig{
		Concurrency:   cfg.TrafficLabels.Concurrency,
		BatchMaxTexts: cfg.TrafficLabels.BatchMaxTexts,
		ClaimMinIdle:  cfg.TrafficLabels.ClaimMinIdle,
		MaxAttempts:   cfg.TrafficLabels.MaxAttempts,
	})
}

func newTrafficLabelsMiddleware(
	intake trafficlabels.Intake,
	metrics *o11y.TrafficLabelsMetrics,
	cfg *config.Config,
) *middleware.TrafficLabelsMiddleware {
	return middleware.NewTrafficLabelsMiddleware(intake, metrics, cfg)
}

type TrafficLabelsParams struct {
	dig.In
	Logger *slog.Logger
	Stream *labelstream.Stream
	Intake trafficlabels.Intake
	Worker trafficlabels.Worker
}

func StartTrafficLabels(p TrafficLabelsParams, withIntake bool) func() {
	ctx, cancel := context.WithTimeout(context.Background(), labelGroupTimeout)
	if err := p.Stream.EnsureGroup(ctx); err != nil {
		p.Logger.Warn("traffic labels: consumer group not created at boot", slog.String("error", err.Error()))
	}
	cancel()
	if withIntake {
		p.Intake.Start()
	}
	p.Worker.Start()
	p.Logger.Info(bootlog.TrafficLabelsStarted, slog.Bool("intake", withIntake), slog.Bool("worker", true))

	return func() {
		if withIntake {
			ctx, cancel := context.WithTimeout(context.Background(), labelShutdownTimeout)
			if err := p.Intake.Shutdown(ctx); err != nil {
				p.Logger.Warn("traffic labels intake shutdown timed out", slog.String("error", err.Error()))
			}
			cancel()
		}
		ctx, cancel := context.WithTimeout(context.Background(), labelShutdownTimeout)
		defer cancel()
		if err := p.Worker.Shutdown(ctx); err != nil {
			p.Logger.Warn("traffic labels worker shutdown timed out", slog.String("error", err.Error()))
		}
		if err := p.Stream.Leave(ctx); err != nil {
			p.Logger.Warn("traffic labels: consumer not removed from the group", slog.String("error", err.Error()))
		}
		p.Logger.Info(bootlog.TrafficLabelsStopped)
	}
}
