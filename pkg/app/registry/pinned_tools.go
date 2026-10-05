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
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
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
	// Total is how many definitions match the filter, across all pages.
	Total int
}

const (
	// DefaultPinnedToolsPage and MaxPinnedToolsPage bound one page of the list.
	DefaultPinnedToolsPage = 100
	MaxPinnedToolsPage     = 500
)

// PinnedToolPage selects a window of the list. Order is fixed: first_seen_at,
// name, fingerprint.
type PinnedToolPage struct {
	Limit  int
	Offset int
}

// DecideToolsInput is one admin decision over stored tool definitions.
type DecideToolsInput struct {
	GatewayID  ids.GatewayID
	RegistryID ids.RegistryID
	Approve    []domain.ToolRef
	Reject     []domain.ToolRef
	// DecidedBy is the authenticated admin, never taken from the request body.
	DecidedBy string
}

// PinToolsInput is the "enable pinning with this confirmed list" request.
type PinToolsInput struct {
	GatewayID  ids.GatewayID
	RegistryID ids.RegistryID
	// Tools is the list the admin confirmed; it may be empty (a server whose
	// tools are per principal starts with none).
	Tools []domain.ToolCandidate
	// DecidedBy is the authenticated admin, never taken from the request body.
	DecidedBy string
}

//go:generate mockery --name=PinnedToolService --dir=. --output=./mocks --filename=pinned_tool_service_mock.go --case=underscore --with-expecter
type PinnedToolService interface {
	// List returns the registry's tool definitions, optionally only those in one
	// status. ErrNotFound when the registry is not the gateway's.
	List(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, status *domain.ToolStatus, page PinnedToolPage) (*PinnedToolList, error)
	// Decide approves and rejects stored definitions atomically, then propagates
	// the change. A definition the registry has no row for is ErrUnknownToolRefs
	// and nothing is applied; one in both lists is ErrInvalidToolDecision.
	Decide(ctx context.Context, in DecideToolsInput) error
	// Pin approves the confirmed tools and switches the registry to the pinned
	// policy in one transaction, then propagates. LLM registries are refused with
	// ErrInvalidToolPolicy. Disabling is a plain registry update to auto.
	Pin(ctx context.Context, in PinToolsInput) (*domain.Registry, error)
}

var _ PinnedToolService = (*pinnedToolService)(nil)

type pinnedToolService struct {
	registries  domain.Repository
	tools       domain.PinnedToolRepository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
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
	page PinnedToolPage,
) (*PinnedToolList, error) {
	reg, err := s.owned(ctx, gatewayID, registryID)
	if err != nil {
		return nil, err
	}
	if page.Limit <= 0 {
		page.Limit = DefaultPinnedToolsPage
	}
	if page.Limit > MaxPinnedToolsPage {
		page.Limit = MaxPinnedToolsPage
	}
	if page.Offset < 0 {
		page.Offset = 0
	}
	stored, total, err := s.tools.ListPage(ctx, gatewayID, registryID, status, page.Limit, page.Offset)
	if err != nil {
		return nil, err
	}
	// The approved definition a pending row is diffed against may be on another
	// page, so it is read by name rather than taken from this page.
	var pendingNames []string
	seen := map[string]struct{}{}
	for _, t := range stored {
		if _, dup := seen[t.Name]; t.Status == domain.ToolStatusPending && !dup {
			seen[t.Name] = struct{}{}
			pendingNames = append(pendingNames, t.Name)
		}
	}
	approvedRows, err := s.tools.ListApproved(ctx, gatewayID, registryID, pendingNames)
	if err != nil {
		return nil, err
	}
	latestApproved := make(map[string]domain.PinnedTool)
	for _, t := range approvedRows {
		if cur, ok := latestApproved[t.Name]; !ok || t.DecidedAt.After(cur.DecidedAt) {
			latestApproved[t.Name] = t
		}
	}
	out := &PinnedToolList{ToolPolicy: reg.ToolPolicy.Normalize(), Items: make([]PinnedToolView, 0, len(stored)), Total: total}
	for _, t := range stored {
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

func (s *pinnedToolService) Decide(ctx context.Context, in DecideToolsInput) error {
	if err := rejectOverlap(in.Approve, in.Reject); err != nil {
		return err
	}
	if len(in.Approve)+len(in.Reject) == 0 {
		return nil
	}
	// The repository decides, checks the refs and bumps the registry (updated_at
	// plus the snapshot change marker) in one transaction.
	if err := s.tools.Decide(ctx, in.GatewayID, in.RegistryID, in.Approve, in.Reject, in.DecidedBy); err != nil {
		return err
	}
	s.propagate(ctx, in.GatewayID, in.RegistryID)
	return nil
}

func (s *pinnedToolService) Pin(ctx context.Context, in PinToolsInput) (*domain.Registry, error) {
	reg, err := s.owned(ctx, in.GatewayID, in.RegistryID)
	if err != nil {
		return nil, err
	}
	if !reg.IsMCP() {
		return nil, fmt.Errorf("%w: pinned is only valid for MCP registries", domain.ErrInvalidToolPolicy)
	}
	// One transaction: the approvals, the policy switch, the registry bump and
	// the snapshot change marker commit together or not at all.
	if err := s.tools.Pin(ctx, in.GatewayID, in.RegistryID, in.Tools, in.DecidedBy); err != nil {
		return nil, err
	}
	if fresh := s.propagate(ctx, in.GatewayID, in.RegistryID); fresh != nil {
		return fresh, nil
	}
	reg.ToolPolicy = domain.ToolPolicyPinned
	return reg, nil
}

func rejectOverlap(approve, reject []domain.ToolRef) error {
	approved := make(map[domain.ToolRef]struct{}, len(approve))
	for _, r := range approve {
		approved[r] = struct{}{}
	}
	for _, r := range reject {
		if _, both := approved[r]; both {
			return fmt.Errorf("%w: %q is in both approve and reject", domain.ErrInvalidToolDecision, r.Name)
		}
	}
	return nil
}

// propagate is what a registry update does once its write committed: refresh
// this pod's cached registry, tell every other replica to drop theirs, and wake
// the snapshot dispatcher. The change marker the repository wrote in the same
// transaction is the durable part: if the invalidation or the signal is lost,
// the dispatcher's backstop still recompiles from the marker.
func (s *pinnedToolService) propagate(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) *domain.Registry {
	fresh, err := s.registries.FindByID(ctx, registryID)
	if err == nil {
		s.memoryCache.Set(registryID.String(), fresh)
	} else {
		fresh = nil
		s.memoryCache.Delete(registryID.String())
		s.logger.Warn("pinned tools: could not reload the registry after a decision; its cache entry was dropped",
			"registry_id", registryID.String(), "error", err)
	}
	invalidation.Registry(ctx, s.publisher, s.logger, gatewayID, registryID)
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
	return fresh
}
