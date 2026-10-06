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

package registry

import (
	"context"
	"log/slog"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// WithPinnedTools decorates the registry repository the MCP data path reads
// (the consumer data finder and the Store scoper) so pinned registries carry
// their decided tool set, the same field the config snapshot carries to DB-less
// planes. On a full-mode pod there is no snapshot: without this the set would
// stay empty and a pinned registry would expose nothing, even after approval.
//
// Writes and admin reads must keep the plain repository; only wrap the readers
// that feed the MCP composer.
//
// A read error is not returned: it would fail the whole gateway load for one
// registry. The registry is returned with an empty set instead, which exposes
// none of its tools (fail closed), and the failure is logged and counted. The
// result is cached with the rest of the consumer data, so the next refresh
// retries.
func WithPinnedTools(repo domain.Repository, pinned domain.PinnedToolLister, logger *slog.Logger) domain.Repository {
	if logger == nil {
		logger = slog.Default()
	}
	return &pinnedReader{Repository: repo, pinned: pinned, logger: logger}
}

type pinnedReader struct {
	domain.Repository
	pinned domain.PinnedToolLister
	logger *slog.Logger
}

func (r *pinnedReader) FindByID(ctx context.Context, id ids.RegistryID) (*domain.Registry, error) {
	reg, err := r.Repository.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	r.stamp(ctx, []*domain.Registry{reg})
	return reg, nil
}

func (r *pinnedReader) FindByIDs(ctx context.Context, gatewayID ids.GatewayID, registryIDs []ids.RegistryID) ([]*domain.Registry, error) {
	regs, err := r.Repository.FindByIDs(ctx, gatewayID, registryIDs)
	if err != nil {
		return nil, err
	}
	r.stamp(ctx, regs)
	return regs, nil
}

func (r *pinnedReader) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Registry, int, error) {
	regs, total, err := r.Repository.List(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	r.stamp(ctx, regs)
	return regs, total, nil
}

// stamp reads one registry at a time so a failure only empties that registry's
// set and the others keep theirs.
func (r *pinnedReader) stamp(ctx context.Context, regs []*domain.Registry) {
	for _, reg := range regs {
		if err := domain.StampPinnedTools(ctx, r.pinned, []*domain.Registry{reg}); err != nil {
			reg.PinnedTools = nil
			r.logger.Warn("registry: failed to read pinned tools; the registry exposes none of its tools until the next refresh",
				"registry_id", reg.ID.String(), "error", err)
			pinnedReadErrors().Add(ctx, 1)
		}
	}
}

var (
	pinnedReadErrorsOnce    sync.Once
	pinnedReadErrorsCounter metric.Int64Counter
)

// pinnedReadErrors resolves the counter once. A failed creation leaves the no-op
// instrument, so a metrics problem never reaches the request path.
func pinnedReadErrors() metric.Int64Counter {
	pinnedReadErrorsOnce.Do(func() {
		c, err := otel.Meter("trustgate/registry").Int64Counter(
			"trustgate.registry.pinned_tools.read_errors",
			metric.WithDescription("pinned registries whose decided tools could not be read, so they expose nothing"),
		)
		if err != nil {
			slog.Warn("failed to create pinned tools read error counter", slog.String("error", err.Error()))
			c = noop.Int64Counter{}
		}
		pinnedReadErrorsCounter = c
	})
	return pinnedReadErrorsCounter
}
