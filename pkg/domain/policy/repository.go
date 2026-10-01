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

package policy

import (
	"context"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
)

var SortableFields = []string{"name", "created_at", "updated_at", "priority"}

type ListFilter struct {
	GatewayID  ids.GatewayID
	Search     string
	Enabled    *bool
	Global     *bool
	Mode       Mode
	Categories []string
	Types      []string
	// RestrictToSlugs with empty Slugs means match nothing (ENG-1242).
	RestrictToSlugs bool
	Slugs           []string
	RegistryID      *ids.RegistryID
	Page            listing.Page
	Sort            listing.Sort
}

// Placement is where a policy row runs after a placement write, with the
// updated_at that write gave it.
type Placement struct {
	Global    bool
	MCPWide   bool
	UpdatedAt time.Time
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=policy_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, p *Policy) error
	// Update persists the columns of p. writeMCPScope false leaves
	// policies.mcp_scope as stored: an update that did not ask to change the
	// scope must not write back the value it read, or it would resurrect a
	// registry a concurrent prune had just removed.
	//
	// Update never writes global or mcp_wide, and it lands only while the
	// stored flags still equal p's: the level check ran on p's placement, so a
	// promotion committed since the read fails the update with
	// ErrPlacementChanged instead of storing a state nobody checked.
	Update(ctx context.Context, p *Policy, writeMCPScope bool) error
	// SetGlobal writes the global flag and returns the placement the row holds
	// after the write. Promoting also clears mcp_wide in the same row write;
	// demoting touches global only, so the result can still be MCP-wide.
	//
	// A non-zero readAt makes the write conditional on the row the caller
	// decided on: it lands only while updated_at still equals readAt, and
	// fails with ErrPlacementChanged otherwise. A promotion passes the
	// updated_at it read, because the level check it ran describes that row
	// and no other; a demotion only releases levels and passes the zero time.
	SetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID, global bool, readAt time.Time) (Placement, error)
	// SetMCPWide writes the mcp_wide flag and returns the placement the row
	// holds after the write. Promoting also clears global in the same row
	// write; demoting touches mcp_wide only. readAt works as in SetGlobal.
	SetMCPWide(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID, mcpWide bool, readAt time.Time) (Placement, error)
	Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) error
	FindByID(ctx context.Context, id ids.PolicyID) (*Policy, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, policyIDs []ids.PolicyID) ([]*Policy, error)
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Policy, error)
	List(ctx context.Context, filter ListFilter) (items []*Policy, total int, err error)
}
