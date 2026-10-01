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
	"log/slog"
	"sort"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	// DefaultAuditDelay gives the plane time to load its tenant caps copy
	// (TenantCapsCache), which the audit needs to map a gateway to its tenant and
	// compare against its monthly cap. The config snapshot is not what it waits
	// for.
	DefaultAuditDelay = 90 * time.Second

	auditName = "per-tenant-rollout"

	releaseTimeout = 5 * time.Second
)

// LegacyCounters reads what the per-gateway counters left behind in Redis.
type LegacyCounters interface {
	// AcquireAudit returns true for exactly one caller per name, so that of all
	// the pods starting together only one does the work.
	AcquireAudit(ctx context.Context, name string) (bool, error)
	// ReleaseAudit gives the claim back when the work failed, so that another
	// pod, or this one on its next boot, can try again.
	ReleaseAudit(ctx context.Context, name string) error
	// LegacyQuotaByGateway returns the quota used this month under the old
	// per-gateway keys.
	LegacyQuotaByGateway(ctx context.Context, month string) (map[ids.GatewayID]int64, error)
}

// RolloutAudit is the one-off report that goes with the move from per-gateway to
// per-tenant counters.
//
// The month in which the new keys are introduced starts from zero: nothing is
// seeded from the old counters, because they cannot be summed safely while old
// pods still write them. That forgives, for one month, whatever a tenant had
// already spent. This audit makes the forgiveness visible: it adds up the old
// per-gateway counters by tenant and logs every tenant whose total already
// exceeded its monthly cap, which is exactly the set the shared pool would have
// been blocking.
//
// It is tied to the month of the rollout: the old counters of any other month
// say nothing about the move, and a run outside it would repeat itself every
// month for nothing. It must also run where the resolver can see every tenant
// (a plane backed by Postgres): on a plane that holds a snapshot scoped to one
// gateway, almost every legacy key would be unresolved and the report would be
// wrong, so the container does not start it there.
type RolloutAudit struct {
	resolver GatewayTierLoader
	legacy   LegacyCounters
	month    string
	delay    time.Duration
	now      func() time.Time
	logger   *slog.Logger
}

// NewRolloutAudit builds the audit for the rollout month ("YYYY-MM"). An empty
// month, or any other month than the current one, makes Once a no-op.
func NewRolloutAudit(resolver GatewayTierLoader, legacy LegacyCounters, month string, logger *slog.Logger) *RolloutAudit {
	return &RolloutAudit{
		resolver: resolver,
		legacy:   legacy,
		month:    month,
		delay:    DefaultAuditDelay,
		now:      time.Now,
		logger:   loggerOrDefault(logger),
	}
}

// AuditReport is what one audit found.
type AuditReport struct {
	Month            string
	LegacyKeys       int
	Tenants          int
	Unresolved       int
	OverQuotaTenants []string
}

// Run waits for the snapshot, then audits once. It returns when done or when ctx
// is cancelled.
func (a *RolloutAudit) Run(ctx context.Context) {
	timer := time.NewTimer(a.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	if _, err := a.Once(ctx); err != nil {
		a.logger.Warn("rate limit rollout audit failed",
			slog.String("component", "ratelimit"), slog.Any("error", err))
	}
}

// Once runs the audit if this is the rollout month and this pod wins the right
// to. A nil report means there was nothing to do: not the rollout month, or
// another pod already did it.
//
// The claim is taken before the scan, so that pods starting together do not all
// scan, and given back if the scan fails: a claim that outlived a failed audit
// would silence it for everyone until the key expired.
func (a *RolloutAudit) Once(ctx context.Context) (*AuditReport, error) {
	month := quotaWindow(a.now())
	if a.month == "" || a.month != month {
		return nil, nil
	}

	name := auditName + ":" + month
	won, err := a.legacy.AcquireAudit(ctx, name)
	if err != nil || !won {
		return nil, err
	}
	report, err := a.scan(ctx, month)
	if err != nil {
		a.release(name)
		return nil, err
	}
	return report, nil
}

// release gives the claim back on a context of its own: the failure that sent
// us here may well be a cancelled one.
func (a *RolloutAudit) release(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
	defer cancel()
	if err := a.legacy.ReleaseAudit(ctx, name); err != nil {
		a.logger.Warn("rate limit rollout audit: failed to release the claim after a failure; it will not run again this month unless the key is removed",
			slog.String("component", "ratelimit"), slog.String("claim", name), slog.Any("error", err))
	}
}

func (a *RolloutAudit) scan(ctx context.Context, month string) (*AuditReport, error) {
	byGateway, err := a.legacy.LegacyQuotaByGateway(ctx, month)
	if err != nil {
		return nil, err
	}

	type tally struct {
		used     int64
		gateways int
		quota    int
	}
	byTenant := map[string]*tally{}
	report := &AuditReport{Month: month, LegacyKeys: len(byGateway)}
	for gatewayID, used := range byGateway {
		resolved, err := a.resolver.Resolve(ctx, gatewayID)
		if err != nil {
			report.Unresolved++
			continue
		}
		t := byTenant[resolved.Subject]
		if t == nil {
			t = &tally{quota: resolved.Limits.QuotaPerMonth}
			byTenant[resolved.Subject] = t
		}
		t.used += used
		t.gateways++
	}
	report.Tenants = len(byTenant)

	for tenant, t := range byTenant {
		if t.quota > 0 && t.used > int64(t.quota) {
			report.OverQuotaTenants = append(report.OverQuotaTenants, tenant)
			a.logger.Warn("rate limit rollout audit: tenant had exceeded its monthly quota under per-gateway counters",
				slog.String("component", "ratelimit"),
				slog.String("tenant_id", tenant),
				slog.String("month", month),
				slog.Int64("used", t.used),
				slog.Int("quota", t.quota),
				slog.Int("gateways", t.gateways))
		}
	}
	sort.Strings(report.OverQuotaTenants)

	a.logger.Info("rate limit rollout audit finished",
		slog.String("component", "ratelimit"),
		slog.String("month", month),
		slog.Int("legacy_keys", report.LegacyKeys),
		slog.Int("tenants", report.Tenants),
		slog.Int("unresolved_gateways", report.Unresolved),
		slog.Int("over_quota_tenants", len(report.OverQuotaTenants)))
	return report, nil
}
