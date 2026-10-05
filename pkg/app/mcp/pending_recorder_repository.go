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

package mcp

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// RepositoryPendingRecorder is the full plane's persistence port for pending
// tools: it writes straight through the pinned tool repository, which only
// inserts missing rows and never touches a decided one. The DB-less plane uses
// the config-sync client instead.
type RepositoryPendingRecorder struct {
	repo   registrydomain.PinnedToolRepository
	logger *slog.Logger
	capped metric.Int64Counter
}

func NewRepositoryPendingRecorder(repo registrydomain.PinnedToolRepository, logger *slog.Logger) *RepositoryPendingRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	capped, err := otel.GetMeterProvider().Meter("trustgate/mcp").Int64Counter(
		"trustgate.pinned_tools.capped",
		metric.WithDescription("new pending tool definitions dropped because a registry or tool name hit its pending cap"))
	if err != nil {
		capped = noop.Int64Counter{}
	}
	return &RepositoryPendingRecorder{repo: repo, logger: logger, capped: capped}
}

var _ PendingToolRecorder = (*RepositoryPendingRecorder)(nil)

func (r *RepositoryPendingRecorder) Record(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	tools []registrydomain.ToolCandidate,
) error {
	_, dropped, err := r.repo.UpsertPending(ctx, gatewayID, registryID, tools)
	if err != nil {
		return fmt.Errorf("pending tools: %w", err)
	}
	if dropped > 0 {
		r.capped.Add(ctx, int64(dropped))
		r.logger.Warn("pending tools: pending cap reached; new definitions were not stored",
			"registry_id", registryID.String(), "dropped", dropped)
	}
	return nil
}
