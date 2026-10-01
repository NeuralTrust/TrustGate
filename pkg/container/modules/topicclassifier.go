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
	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/topiccache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/topicguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/topicstream"
	"go.uber.org/dig"
)

const (
	topicGroupTimeout    = 5 * time.Second
	topicShutdownTimeout = 5 * time.Second

	topicCacheKeyInfo = "trustgate/topic-classifier-cache"
	topicCacheKeyLen  = 32
)

func TopicClassifier(c *container.Container) error {
	for _, provider := range []any{
		newTopicStream,
		newTopicClassifierMetrics,
		newTopicGuardClient,
		newTopicCache,
		newTopicSink,
		newTopicIntake,
		newTopicWorker,
		newTopicClassificationMiddleware,
	} {
		if err := c.Provide(provider); err != nil {
			return err
		}
	}
	return nil
}

func newTopicStream(cc cache.Client, cfg *config.Config) *topicstream.Stream {
	return topicstream.New(cc.RedisClient(), topicstream.Config{
		MaxLen:                cfg.TopicClassifier.StreamMaxLen,
		Retention:             cfg.TopicClassifier.StreamRetention,
		GatewayQuotaPerSecond: cfg.TopicClassifier.GatewayQuotaPerSecond,
	})
}

func newTopicClassifierMetrics(cfg *config.Config, sdk *o11y.SDK, stream *topicstream.Stream) (*o11y.TopicClassifierMetrics, error) {
	return o11y.NewTopicClassifierMetrics(cfg, sdk, stream.Stats)
}

func newTopicGuardClient(cfg *config.Config) *topicguard.Client {
	return topicguard.NewClient(
		cfg.FirewallComplexity.BaseURL,
		firewall.NewTokenProvider(cfg.FirewallComplexity.SecretKey),
		cfg.TopicClassifier.ClassifierTimeout,
	)
}

// The unused Encrypter forces SERVER_SECRET_KEY to be resolved in prod before it is read.
func newTopicCache(cc cache.Client, cfg *config.Config, _ vaultdomain.Encrypter, logger *slog.Logger) topicclassifier.Cache {
	secret := cfg.Server.SecretKey
	if secret == "" {
		logger.Warn("topic classifier: SERVER_SECRET_KEY is not set, classifications are not cached")
		return nil
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, topicCacheKeyInfo, topicCacheKeyLen)
	if err != nil {
		logger.Warn("topic classifier: cache key not derived, classifications are not cached", slog.String("error", err.Error()))
		return nil
	}
	return topiccache.New(cc.RedisClient(), cfg.TopicClassifier.CacheTTL, key)
}

func newTopicSink(gateways gatewaydomain.Repository, pipeline *appmetrics.Pipeline) topicclassifier.Sink {
	return topicclassifier.NewEventSink(gateways, pipeline)
}

func newTopicIntake(
	logger *slog.Logger,
	registry *adapter.Registry,
	stream *topicstream.Stream,
	metrics *o11y.TopicClassifierMetrics,
	cfg *config.Config,
) topicclassifier.Intake {
	return topicclassifier.NewIntake(logger, registry, stream, metrics, topicclassifier.IntakeConfig{
		QueueSize:      cfg.TopicClassifier.IntakeQueueSize,
		Workers:        cfg.TopicClassifier.IntakeWorkers,
		EnqueueTimeout: cfg.TopicClassifier.EnqueueTimeout,
		MaxBufferBytes: cfg.TopicClassifier.IntakeMaxBufferBytes,
	})
}

func newTopicWorker(
	logger *slog.Logger,
	stream *topicstream.Stream,
	client *topicguard.Client,
	classificationCache topicclassifier.Cache,
	sink topicclassifier.Sink,
	metrics *o11y.TopicClassifierMetrics,
	cfg *config.Config,
) topicclassifier.Worker {
	return topicclassifier.NewWorker(logger, stream, client, classificationCache, sink, metrics, topicclassifier.WorkerConfig{
		Concurrency:   cfg.TopicClassifier.Concurrency,
		BatchMaxTexts: cfg.TopicClassifier.BatchMaxTexts,
		ClaimMinIdle:  cfg.TopicClassifier.ClaimMinIdle,
		MaxAttempts:   cfg.TopicClassifier.MaxAttempts,
	})
}

func newTopicClassificationMiddleware(
	intake topicclassifier.Intake,
	metrics *o11y.TopicClassifierMetrics,
	cfg *config.Config,
) *middleware.TopicClassificationMiddleware {
	return middleware.NewTopicClassificationMiddleware(intake, metrics, cfg)
}

type TopicClassifierParams struct {
	dig.In
	Logger     *slog.Logger
	Stream     *topicstream.Stream
	Classifier *topicguard.Client
	Intake     topicclassifier.Intake
	Worker     topicclassifier.Worker
}

func StartTopicClassifier(p TopicClassifierParams, withIntake bool) func() {
	ctx, cancel := context.WithTimeout(context.Background(), topicGroupTimeout)
	if err := p.Stream.EnsureGroup(ctx); err != nil {
		p.Logger.Warn("topic classifier: consumer group not created at boot", slog.String("error", err.Error()))
	}
	cancel()
	if withIntake {
		p.Intake.Start()
	}
	withWorker := p.Classifier.Configured()
	if withWorker {
		p.Worker.Start()
	} else {
		p.Logger.Warn("topic classifier: no topic-guard endpoint configured (FIREWALL_BASE_URL, FIREWALL_SECRET_KEY), this plane does not classify")
	}
	p.Logger.Info(bootlog.TopicClassifierStarted, slog.Bool("intake", withIntake), slog.Bool("worker", withWorker))

	return func() {
		if withIntake {
			ctx, cancel := context.WithTimeout(context.Background(), topicShutdownTimeout)
			if err := p.Intake.Shutdown(ctx); err != nil {
				p.Logger.Warn("topic classifier intake shutdown timed out", slog.String("error", err.Error()))
			}
			cancel()
		}
		ctx, cancel := context.WithTimeout(context.Background(), topicShutdownTimeout)
		defer cancel()
		if err := p.Worker.Shutdown(ctx); err != nil {
			p.Logger.Warn("topic classifier worker shutdown timed out", slog.String("error", err.Error()))
		}
		if withWorker {
			if err := p.Stream.Leave(ctx); err != nil {
				p.Logger.Warn("topic classifier: consumer not removed from the group", slog.String("error", err.Error()))
			}
		}
		p.Logger.Info(bootlog.TopicClassifierStopped)
	}
}
