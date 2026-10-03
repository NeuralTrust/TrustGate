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

package proxy

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/singleflight"
)

const (
	headerMaxTokensClamped = "X-Max-Tokens-Clamped" // #nosec G101 -- HTTP header name, not a credential

	clampSourceCatalog  = "catalog"
	clampSourceLearned  = "learned"
	clampSourceUpstream = "upstream"
)

// CatalogReader is the catalog lookup the proxy uses for output-token limits
// and context-window preflight.
type CatalogReader interface {
	FindModel(ctx context.Context, providerCode, slug string) (*catalogdomain.Model, error)
}

type cachedOutputLimit struct {
	n      int
	source string
}

type outputLimits struct {
	reader CatalogReader
	cache  *cache.TTLMap
	sf     singleflight.Group
	logger *slog.Logger
	metric metric.Int64Counter
}

func newOutputLimits(reader CatalogReader, logger *slog.Logger) *outputLimits {
	if logger == nil {
		logger = slog.Default()
	}
	counter, err := otel.Meter("trustgate/proxy").Int64Counter(
		"trustgate.proxy.max_tokens_clamped",
		metric.WithDescription("requests whose max output tokens were clamped to a model limit"),
	)
	if err != nil {
		logger.Warn("failed to create max-tokens clamp counter; clamps will only be logged",
			slog.String("error", err.Error()))
		counter = nil
	}
	return &outputLimits{
		reader: reader,
		cache:  cache.NewTTLMap(cache.OutputLimitCacheTTL),
		logger: logger,
		metric: counter,
	}
}

func (l *outputLimits) Limit(ctx context.Context, providerCode, slug string) (int, string) {
	if l == nil || l.reader == nil || providerCode == "" || slug == "" {
		return 0, ""
	}
	key := providerCode + ":" + slug
	if cached, ok := l.cached(key); ok {
		return cached.n, cached.source
	}
	v, _, _ := l.sf.Do(key, func() (interface{}, error) {
		if cached, ok := l.cached(key); ok {
			return cached, nil
		}
		entry := l.load(ctx, providerCode, slug)
		if entry.n == 0 && providerCode == provider.OpenAICompatible {
			entry = l.load(ctx, provider.OpenAI, slug)
		}
		l.cache.Set(key, entry)
		return entry, nil
	})
	got, _ := v.(cachedOutputLimit)
	return got.n, got.source
}

func (l *outputLimits) Learn(providerCode, slug string, n int) {
	if l == nil || n <= 0 || providerCode == "" || slug == "" {
		return
	}
	l.cache.Set(providerCode+":"+slug, cachedOutputLimit{n: n, source: clampSourceLearned})
}

func (l *outputLimits) record(ctx context.Context, providerCode, source string) {
	if l == nil || l.metric == nil {
		return
	}
	l.metric.Add(ctx, 1, metric.WithAttributes(
		attribute.String("provider", providerCode),
		attribute.String("source", source),
	))
}

func (l *outputLimits) cached(key string) (cachedOutputLimit, bool) {
	cached, ok := l.cache.Get(key)
	if !ok {
		return cachedOutputLimit{}, false
	}
	entry, ok := cached.(cachedOutputLimit)
	if !ok {
		l.cache.Delete(key)
		return cachedOutputLimit{}, false
	}
	return entry, true
}

func (l *outputLimits) load(ctx context.Context, providerCode, slug string) cachedOutputLimit {
	model, err := l.reader.FindModel(ctx, providerCode, slug)
	if err != nil {
		if !errors.Is(err, commonerrors.ErrNotFound) {
			l.logger.Debug("catalog output-limit lookup failed",
				slog.String("provider", providerCode),
				slog.String("model", slug),
				slog.String("error", err.Error()))
		}
		return cachedOutputLimit{}
	}
	if model == nil || model.MaxOutput <= 0 {
		return cachedOutputLimit{}
	}
	return cachedOutputLimit{n: model.MaxOutput, source: clampSourceCatalog}
}

func (p *providerInvoker) applyOutputLimit(ctx context.Context, prep *preparedInvocation) {
	if p.limits == nil || prep == nil || prep.capability != capabilityChat {
		return
	}
	limit, source := p.limits.Limit(ctx, prep.providerName, prep.sentModel)
	if limit <= 0 {
		return
	}
	out, requested, clamped := adapter.ClampMaxOutputTokens(prep.body, limit)
	if !clamped {
		return
	}
	prep.body = out
	prep.clampedTo = limit
	prep.clampSource = source
	p.logger.Info("clamped max output tokens",
		slog.String("provider", prep.providerName),
		slog.String("model", prep.sentModel),
		slog.Int("requested", requested),
		slog.Int("limit", limit),
		slog.String("source", source))
	p.limits.record(ctx, prep.providerName, source)
}

func withOutputLimitHeader(headers map[string][]string, prep *preparedInvocation) map[string][]string {
	if prep == nil || prep.clampedTo <= 0 {
		return headers
	}
	if headers == nil {
		headers = make(map[string][]string)
	}
	headers[headerMaxTokensClamped] = []string{strconv.Itoa(prep.clampedTo)}
	return headers
}
