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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

// PinnedToolView is one stored definition of a pinned registry as an admin sees
// it. For a pending row whose name also has an approved row, Approved is the
// approved definition (the most recently decided one), so a UI can show what
// changed.
type PinnedToolView struct {
	domain.PinnedTool
	Approved *domain.PinnedTool
}

// PinnedToolList is a registry's stored tool definitions plus the policy they
// are judged under.
type PinnedToolList struct {
	ToolPolicy domain.ToolPolicy
	Items      []PinnedToolView
}

//go:generate mockery --name=PinnedToolService --dir=. --output=./mocks --filename=pinned_tool_service_mock.go --case=underscore --with-expecter
type PinnedToolService interface {
	// List returns the registry's tool definitions, optionally only those in one
	// status. ErrNotFound when the registry is not the gateway's.
	List(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, status *domain.ToolStatus) (*PinnedToolList, error)
}

var _ PinnedToolService = (*pinnedToolService)(nil)

type pinnedToolService struct {
	registries  domain.Repository
	tools       domain.PinnedToolRepository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	now         func() time.Time
}

func NewPinnedToolService(
	registries domain.Repository,
	tools domain.PinnedToolRepository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
) PinnedToolService {
	return &pinnedToolService{
		registries:  registries,
		tools:       tools,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
		now:         time.Now,
	}
}

// owned loads the registry and refuses one that belongs to another gateway as
// if it did not exist, like every other gateway-scoped admin read.
func (s *pinnedToolService) owned(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) (*domain.Registry, error) {
	reg, err := s.registries.FindByID(ctx, registryID)
	if err != nil {
		return nil, err
	}
	if reg.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	return reg, nil
}

func (s *pinnedToolService) List(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	status *domain.ToolStatus,
) (*PinnedToolList, error) {
	reg, err := s.owned(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	stored, err := s.tools.ListByRegistry(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	latestApproved := make(map[string]domain.PinnedTool)
	for _, t := range stored {
		if t.Status != domain.ToolStatusApproved {
			continue
		}
		if cur, ok := latestApproved[t.Name]; !ok || t.DecidedAt.After(cur.DecidedAt) {
			latestApproved[t.Name] = t
		}
	}
	out := &PinnedToolList{ToolPolicy: reg.ToolPolicy.Normalize(), Items: make([]PinnedToolView, 0, len(stored))}
	for _, t := range stored {
		if status != nil && t.Status != *status {
			continue
		}
		view := PinnedToolView{PinnedTool: t}
		if t.Status == domain.ToolStatusPending {
			if a, ok := latestApproved[t.Name]; ok {
				approved := a
				view.Approved = &approved
			}
		}
		out.Items = append(out.Items, view)
	}
	return out, nil
}
