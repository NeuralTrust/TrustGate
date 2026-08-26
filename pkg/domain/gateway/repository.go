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

package gateway

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type ListFilter struct {
	SlugContains string
	// TenantID scopes results to one tenant; empty means no tenant filter (platform-wide).
	TenantID string
	Page     int
	Size     int
}

// RestampedGateway identifies a gateway a re-stamp touched. It carries the slug as
// well as the id because gateways are cached under both keys — dropping only the id
// entry would leave FindBySlug serving the old plan.
type RestampedGateway struct {
	ID   ids.GatewayID
	Slug string
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=gateway_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, g *Gateway) error
	Update(ctx context.Context, g *Gateway) error
	Delete(ctx context.Context, id ids.GatewayID) error
	FindByID(ctx context.Context, id ids.GatewayID) (*Gateway, error)
	FindByDomain(ctx context.Context, domain string) (*Gateway, error)
	FindBySlug(ctx context.Context, slug string) (*Gateway, error)
	List(ctx context.Context, filter ListFilter) (items []*Gateway, total int, err error)
	CountByTenantID(ctx context.Context, tenantID string) (int, error)
	// SaveWithTenantCap atomically enforces maxInstances for tenantID before inserting g; maxInstances <= 0 means unlimited.
	SaveWithTenantCap(ctx context.Context, g *Gateway, tenantID string, maxInstances int) error
	// UpdateWithTenantCap updates g under the same tenant advisory lock used by SaveWithTenantCap when maxInstances > 0.
	UpdateWithTenantCap(ctx context.Context, g *Gateway, tenantID string, maxInstances int) error
	// RestampEntitlementsByTenantID writes e onto every gateway of the tenant and
	// returns the ids it touched.
	//
	// Deliberately uncapped: a plan change is a fact the control plane has already
	// committed, and refusing to propagate a downgrade would leave every gateway of
	// the tenant on the old plan. Instance caps still bind on create, where they
	// prevent growth.
	RestampEntitlementsByTenantID(ctx context.Context, tenantID string, e Entitlements) ([]RestampedGateway, error)
}
