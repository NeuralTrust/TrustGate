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

package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

// mcpTargetSwapper is the registry write that locks the row and updates only
// mcp_target. The domain Repository stays free of it so snapshot fakes do not
// have to implement a catalog compare-and-swap.
type mcpTargetSwapper interface {
	CompareAndSwapMCPTarget(
		ctx context.Context,
		gatewayID ids.GatewayID,
		id ids.RegistryID,
		updatedAt time.Time,
		match func(current *registrydomain.MCPTarget) (next *registrydomain.MCPTarget, ok bool),
	) (bool, error)
}

// catalogTargetSaver writes a reconciled mcp_target under a row lock, then the
// in-memory cache, the invalidation event, and the config-sync signal. It does
// not run Updater, which would reject a catalog shape that still needs an
// admin secret, and it does not write the registry's name or description.
type catalogTargetSaver struct {
	repo      registrydomain.Repository
	memory    *cache.TTLMap
	publisher cache.EventPublisher
	signaler  configsyncport.SnapshotSignaler
	logger    *slog.Logger
}

// NewCatalogTargetSaver builds the control-plane writer. memory, publisher,
// signaler, and logger may be nil.
func NewCatalogTargetSaver(
	repo registrydomain.Repository,
	memory *cache.TTLMap,
	publisher cache.EventPublisher,
	signaler configsyncport.SnapshotSignaler,
	logger *slog.Logger,
) (CatalogTargetSaver, error) {
	if repo == nil {
		return nil, ErrUnavailable
	}
	return &catalogTargetSaver{
		repo:      repo,
		memory:    memory,
		publisher: publisher,
		signaler:  signaler,
		logger:    logger,
	}, nil
}

func (s *catalogTargetSaver) SaveCatalogTarget(ctx context.Context, reg *registrydomain.Registry, oldFP string) (bool, error) {
	if reg == nil || reg.MCPTarget == nil {
		return false, ErrUnavailable
	}
	swapper, ok := s.repo.(mcpTargetSwapper)
	if !ok {
		return false, fmt.Errorf("store: registry repository cannot compare-and-swap a catalog target")
	}
	applied, err := swapper.CompareAndSwapMCPTarget(ctx, reg.GatewayID, reg.ID, reg.UpdatedAt, catalogSwap(oldFP, reg.MCPTarget))
	if err != nil || !applied {
		return false, err
	}
	if s.memory != nil {
		s.memory.Set(reg.ID.String(), reg)
	}
	invalidation.Registry(ctx, s.publisher, s.logger, reg.GatewayID, reg.ID)
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
	return true, nil
}
