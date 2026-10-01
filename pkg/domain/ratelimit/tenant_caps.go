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

package ratelimit

import (
	"context"
	"math"
)

// MaxCap is the largest value a plan cap may take. The caps are persisted as
// INTEGER columns and travel in the config snapshot as int32, so a larger
// number would wrap or abort a write; it is refused where the plan is stamped.
const MaxCap = math.MaxInt32

// TenantCaps are the plan caps of one tenant. They are the single source of the
// numbers a counter is compared against: every gateway of the tenant adds to the
// same counter, so the cap has to be a property of the tenant and not of
// whichever gateway happened to receive the request.
//
// The control plane writes them when it restamps a tenant (and on the first
// stamped create for a tenant that has none yet); the data plane reads them
// from the config snapshot or, where it reads Postgres, from a polled copy.
type TenantCaps struct {
	TenantID      string
	Tier          string
	BurstPerMin   int
	QuotaPerMonth int
	MaxInstances  int
}

// Limits returns the numeric caps.
func (c TenantCaps) Limits() Limits {
	return Limits{
		BurstPerMin:   c.BurstPerMin,
		QuotaPerMonth: c.QuotaPerMonth,
		MaxInstances:  c.MaxInstances,
	}
}

// TenantCapsLister reads every tenant's caps in one query.
type TenantCapsLister interface {
	ListTenantCaps(ctx context.Context) ([]TenantCaps, error)
}

// TenantCapsRepository is the persisted side of the per-tenant caps.
type TenantCapsRepository interface {
	TenantCapsLister
	// GetTenantCaps returns the tenant's caps, or commonerrors.ErrNotFound when
	// none were ever stamped for it.
	GetTenantCaps(ctx context.Context, tenantID string) (*TenantCaps, error)
}
