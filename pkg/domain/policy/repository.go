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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
)

// SortableFields are the whitelist of query fields accepted by list sort.
var SortableFields = []string{"name", "created_at", "updated_at", "priority"}

type ListFilter struct {
	GatewayID ids.GatewayID
	Search    string
	Enabled   *bool
	Global    *bool
	Mode      Mode
	// Categories are catalog group type strings (e.g. "Guardrails"). Expanded to
	// slugs in the app layer before the repository query.
	Categories []string
	// Types are plugin slugs (FE filter id "type"). Combined with Categories via
	// intersection when both are set.
	Types []string
	// RestrictToSlugs, when true, limits results to Slugs (empty Slugs → no rows).
	RestrictToSlugs bool
	Slugs           []string
	Page            listing.Page
	Sort            listing.Sort
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=policy_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, p *Policy) error
	Update(ctx context.Context, p *Policy) error
	SetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID, global bool) error
	Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) error
	FindByID(ctx context.Context, id ids.PolicyID) (*Policy, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, policyIDs []ids.PolicyID) ([]*Policy, error)
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Policy, error)
	List(ctx context.Context, filter ListFilter) (items []*Policy, total int, err error)
}
