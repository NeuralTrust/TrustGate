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

package storeaccess

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ErrInvalidAgentAccess wraps every validation failure of an AgentAccess row.
var ErrInvalidAgentAccess = fmt.Errorf("store agent access: invalid row: %w", commonerrors.ErrValidation)

// PrincipalAll names everyone on the gateway; its PrincipalID is empty.
const PrincipalAll PrincipalType = "all"

// Agent access modes.
const (
	AgentModeAll      = "all"
	AgentModeSelected = "selected"
	AgentModeNone     = "none"
)

// AgentAccess is which of a gateway's A2A agents one principal may call from
// the Employee portal: every enabled agent, the selected ones, or none.
type AgentAccess struct {
	GatewayID     ids.GatewayID    `json:"gateway_id"`
	PrincipalType PrincipalType    `json:"principal_type"`
	PrincipalID   string           `json:"principal_id"`
	Mode          string           `json:"mode"`
	RegistryIDs   []ids.RegistryID `json:"registry_ids,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// NewAgentAccess builds a validated row. Registry ids are kept only for
// "selected", de-duplicated and sorted, so two equal rows serialise
// identically.
func NewAgentAccess(gatewayID ids.GatewayID, principalType PrincipalType, principalID, mode string, registryIDs []ids.RegistryID) (*AgentAccess, error) {
	a := &AgentAccess{
		GatewayID:     gatewayID,
		PrincipalType: principalType,
		PrincipalID:   strings.TrimSpace(principalID),
		Mode:          strings.ToLower(strings.TrimSpace(mode)),
	}
	if a.Mode == AgentModeSelected {
		a.RegistryIDs = normalizeRegistryIDs(registryIDs)
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	a.CreatedAt, a.UpdatedAt = now, now
	return a, nil
}

// Validate checks the gateway, the principal and the mode. The principal id is
// empty exactly for "all".
func (a *AgentAccess) Validate() error {
	if a == nil {
		return fmt.Errorf("%w: nil row", ErrInvalidAgentAccess)
	}
	if a.GatewayID.IsNil() {
		return fmt.Errorf("%w: gateway id is required", ErrInvalidAgentAccess)
	}
	switch a.PrincipalType {
	case PrincipalAll:
		if a.PrincipalID != "" {
			return fmt.Errorf("%w: principal id must be empty for all", ErrInvalidAgentAccess)
		}
	case PrincipalGroup, PrincipalUser:
		if a.PrincipalID == "" {
			return fmt.Errorf("%w: principal id is required", ErrInvalidAgentAccess)
		}
	default:
		return fmt.Errorf("%w: principal type must be all, group or user", ErrInvalidAgentAccess)
	}
	switch a.Mode {
	case AgentModeAll, AgentModeNone:
		if len(a.RegistryIDs) > 0 {
			return fmt.Errorf("%w: registry ids are only for selected", ErrInvalidAgentAccess)
		}
	case AgentModeSelected:
	default:
		return fmt.Errorf("%w: mode must be all, selected or none", ErrInvalidAgentAccess)
	}
	return nil
}

// AgentsFor returns the agents, of those given (the gateway's enabled A2A
// registries), that a person with this subject and these groups may call, in
// the order given. Their own "none" row gives nothing; without an own row, a
// "none" on any of their groups gives nothing; otherwise their own row, their
// groups' rows and the "all" row add up. No rows give nothing. A group key has
// no subject and is judged by its groups and the "all" row.
func AgentsFor(rows []*AgentAccess, subject string, groups []string, agents []ids.RegistryID) []ids.RegistryID {
	subject = strings.TrimSpace(subject)
	member := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		if g = strings.TrimSpace(g); g != "" {
			member[g] = struct{}{}
		}
	}
	var own *AgentAccess
	applying := make([]*AgentAccess, 0, len(rows))
	groupNone := false
	for _, row := range rows {
		if row == nil {
			continue
		}
		switch row.PrincipalType {
		case PrincipalUser:
			if subject != "" && row.PrincipalID == subject {
				own = row
				applying = append(applying, row)
			}
		case PrincipalGroup:
			if _, ok := member[row.PrincipalID]; ok {
				groupNone = groupNone || row.Mode == AgentModeNone
				applying = append(applying, row)
			}
		case PrincipalAll:
			applying = append(applying, row)
		}
	}
	if (own != nil && own.Mode == AgentModeNone) || (own == nil && groupNone) {
		return nil
	}
	every := false
	picked := make(map[ids.RegistryID]struct{})
	for _, row := range applying {
		switch row.Mode {
		case AgentModeAll:
			every = true
		case AgentModeSelected:
			for _, id := range row.RegistryIDs {
				picked[id] = struct{}{}
			}
		}
	}
	out := make([]ids.RegistryID, 0, len(agents))
	for _, id := range agents {
		if _, ok := picked[id]; every || ok {
			out = append(out, id)
		}
	}
	return out
}

func normalizeRegistryIDs(in []ids.RegistryID) []ids.RegistryID {
	seen := make(map[ids.RegistryID]struct{}, len(in))
	out := make([]ids.RegistryID, 0, len(in))
	for _, id := range in {
		if id.IsNil() {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// AgentAccessReader is the read side every plane has: a gateway's agent
// access rows.
type AgentAccessReader interface {
	ListAgentAccessByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*AgentAccess, error)
}

// AgentAccessRepository is the control-plane store, keyed by
// (gateway, principal type, principal id).
//
//go:generate mockery --name=AgentAccessRepository --dir=. --output=./mocks --filename=store_agent_access_repository_mock.go --case=underscore --with-expecter
type AgentAccessRepository interface {
	AgentAccessReader
	// ListAgentAccess pages every row across gateways (snapshot compiler).
	ListAgentAccess(ctx context.Context, page, size int) ([]*AgentAccess, int, error)
	// UpsertAgentAccess creates or replaces the principal's row.
	UpsertAgentAccess(ctx context.Context, a *AgentAccess) error
	// DeleteAgentAccess removes the principal's row; missing is not an error.
	DeleteAgentAccess(ctx context.Context, gatewayID ids.GatewayID, principalType PrincipalType, principalID string) error
	// PruneAgentRegistry drops registryID from every row of the gateway.
	PruneAgentRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error
}
