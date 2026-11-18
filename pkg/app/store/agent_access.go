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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// ErrUnknownAgent is a registry id that is not an A2A registry of the gateway.
var ErrUnknownAgent = fmt.Errorf("store: unknown agent: %w", commonerrors.ErrValidation)

// AgentAccessService is the admin surface over which A2A agents each principal
// may call from the Employee portal: list a gateway's rows and set (or clear)
// one. Every write signals a snapshot rebuild so the data planes pick it up.
//
//go:generate mockery --name=AgentAccessService --dir=. --output=./mocks --filename=store_agent_access_service_mock.go --case=underscore --with-expecter
type AgentAccessService interface {
	storeaccessdomain.AgentAccessReader
	// Set replaces the principal's row; an empty Mode deletes it.
	Set(ctx context.Context, in SetAgentAccessRequest) (*storeaccessdomain.AgentAccess, error)
}

// SetAgentAccessRequest is one row to write. Mode "" means "delete the row".
type SetAgentAccessRequest struct {
	GatewayID     ids.GatewayID
	PrincipalType storeaccessdomain.PrincipalType
	PrincipalID   string
	Mode          string
	RegistryIDs   []ids.RegistryID
}

type agentAccessService struct {
	repo       storeaccessdomain.AgentAccessRepository
	registries RegistryLister
	signaler   configsyncport.SnapshotSignaler
}

// NewAgentAccessService wires the agent access admin service. registries
// checks that every picked id is an A2A registry of the gateway; signaler may
// be nil.
func NewAgentAccessService(
	repo storeaccessdomain.AgentAccessRepository,
	registries RegistryLister,
	signaler configsyncport.SnapshotSignaler,
) (AgentAccessService, error) {
	if repo == nil || registries == nil {
		return nil, ErrUnavailable
	}
	return &agentAccessService{repo: repo, registries: registries, signaler: signaler}, nil
}

func (s *agentAccessService) ListAgentAccessByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*storeaccessdomain.AgentAccess, error) {
	return s.repo.ListAgentAccessByGateway(ctx, gatewayID)
}

func (s *agentAccessService) Set(ctx context.Context, in SetAgentAccessRequest) (*storeaccessdomain.AgentAccess, error) {
	if strings.TrimSpace(in.Mode) == "" {
		probe, err := storeaccessdomain.NewAgentAccess(in.GatewayID, in.PrincipalType, in.PrincipalID, storeaccessdomain.AgentModeNone, nil)
		if err != nil {
			return nil, err
		}
		if err := s.repo.DeleteAgentAccess(ctx, probe.GatewayID, probe.PrincipalType, probe.PrincipalID); err != nil {
			return nil, err
		}
		s.signal(ctx)
		return nil, nil
	}
	row, err := storeaccessdomain.NewAgentAccess(in.GatewayID, in.PrincipalType, in.PrincipalID, in.Mode, in.RegistryIDs)
	if err != nil {
		return nil, err
	}
	if err := s.validateAgents(ctx, row.GatewayID, row.RegistryIDs); err != nil {
		return nil, err
	}
	if err := s.repo.UpsertAgentAccess(ctx, row); err != nil {
		return nil, err
	}
	s.signal(ctx)
	return row, nil
}

func (s *agentAccessService) validateAgents(ctx context.Context, gatewayID ids.GatewayID, picked []ids.RegistryID) error {
	if len(picked) == 0 {
		return nil
	}
	registries, err := listRegistriesByGateway(ctx, s.registries, gatewayID)
	if err != nil {
		return err
	}
	agents := make(map[ids.RegistryID]struct{}, len(registries))
	for _, r := range registries {
		if r.GatewayID == gatewayID && r.Type == registrydomain.TypeA2A {
			agents[r.ID] = struct{}{}
		}
	}
	for _, id := range picked {
		if _, ok := agents[id]; !ok {
			return fmt.Errorf("%w: %s is not an A2A registry of this gateway", ErrUnknownAgent, id)
		}
	}
	return nil
}

func (s *agentAccessService) signal(ctx context.Context) {
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
}

// AgentAccessRegistryCleaner drops a deleted registry from every agent access
// row of its gateway.
type AgentAccessRegistryCleaner struct {
	repo storeaccessdomain.AgentAccessRepository
}

// NewAgentAccessRegistryCleaner wires the cleaner over the agent access
// repository.
func NewAgentAccessRegistryCleaner(repo storeaccessdomain.AgentAccessRepository) *AgentAccessRegistryCleaner {
	return &AgentAccessRegistryCleaner{repo: repo}
}

// DeleteByRegistry removes registryID from the gateway's rows.
func (c *AgentAccessRegistryCleaner) DeleteByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error {
	return c.repo.PruneAgentRegistry(ctx, gatewayID, registryID)
}
