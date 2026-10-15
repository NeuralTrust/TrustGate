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
	"errors"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/jackc/pgx/v5"
)

const tenantCapsColumns = `tenant_id, tier, burst_per_min, quota_per_month, max_instances`

var _ ratelimitdomain.TenantCapsRepository = (*Repository)(nil)

// upsertTenantCaps is the restamp path: the control plane has just said what the
// tenant's plan is, so whatever was there is replaced.
func upsertTenantCaps(ctx context.Context, tx pgx.Tx, tenantID, tier string, l ratelimitdomain.Limits) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO tenant_entitlements (tenant_id, tier, burst_per_min, quota_per_month, max_instances, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (tenant_id) DO UPDATE
		SET tier = EXCLUDED.tier,
		    burst_per_min = EXCLUDED.burst_per_min,
		    quota_per_month = EXCLUDED.quota_per_month,
		    max_instances = EXCLUDED.max_instances,
		    updated_at = NOW()`,
		tenantID, tier, l.BurstPerMin, l.QuotaPerMonth, l.MaxInstances)
	return mapPgError(err)
}

// seedTenantCaps is the create path. A stamped create may carry a stale copy of
// the plan, since it is written once and never revisited, while the tenant's row
// is kept current by every restamp. So it only fills a gap and never overwrites.
func seedTenantCaps(ctx context.Context, tx pgx.Tx, tenantID, tier string, l ratelimitdomain.Limits) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO tenant_entitlements (tenant_id, tier, burst_per_min, quota_per_month, max_instances)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id) DO NOTHING`,
		tenantID, tier, l.BurstPerMin, l.QuotaPerMonth, l.MaxInstances)
	return mapPgError(err)
}

// GetTenantCaps returns the tenant's plan caps, or commonerrors.ErrNotFound when
// none were ever stamped for it.
func (r *Repository) GetTenantCaps(ctx context.Context, tenantID string) (*ratelimitdomain.TenantCaps, error) {
	row := r.conn.Pool.QueryRow(ctx,
		`SELECT `+tenantCapsColumns+` FROM tenant_entitlements WHERE tenant_id = $1`, tenantID)
	var c ratelimitdomain.TenantCaps
	if err := row.Scan(&c.TenantID, &c.Tier, &c.BurstPerMin, &c.QuotaPerMonth, &c.MaxInstances); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, commonerrors.ErrNotFound
		}
		return nil, mapPgError(err)
	}
	return &c, nil
}

// ListTenantCaps returns every tenant's caps.
func (r *Repository) ListTenantCaps(ctx context.Context) ([]ratelimitdomain.TenantCaps, error) {
	rows, err := r.conn.Pool.Query(ctx,
		`SELECT `+tenantCapsColumns+` FROM tenant_entitlements ORDER BY tenant_id`)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()

	var out []ratelimitdomain.TenantCaps
	for rows.Next() {
		var c ratelimitdomain.TenantCaps
		if err := rows.Scan(&c.TenantID, &c.Tier, &c.BurstPerMin, &c.QuotaPerMonth, &c.MaxInstances); err != nil {
			return nil, mapPgError(err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapPgError(err)
	}
	return out, nil
}
