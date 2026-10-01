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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeLegacy struct {
	byGateway map[ids.GatewayID]int64
	taken     map[string]bool
	err       error
	scanErr   error
	// scanned counts the scans, to prove who did the work.
	scanned int
}

func (f *fakeLegacy) ReleaseAudit(_ context.Context, name string) error {
	delete(f.taken, name)
	return nil
}

func (f *fakeLegacy) AcquireAudit(_ context.Context, name string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.taken == nil {
		f.taken = map[string]bool{}
	}
	if f.taken[name] {
		return false, nil
	}
	f.taken[name] = true
	return true, nil
}

func (f *fakeLegacy) LegacyQuotaByGateway(context.Context, string) (map[ids.GatewayID]int64, error) {
	f.scanned++
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	return f.byGateway, f.err
}

func auditFixture(t *testing.T) (*RolloutAudit, *fakeLegacy, *bytes.Buffer) {
	t.Helper()
	r := newResolver()
	a1, a2, b1, orphan := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	std := domain.Limits{BurstPerMin: 300, QuotaPerMonth: 100}
	r.set(a1, "tenant-a", std)
	r.set(a2, "tenant-a", std)
	r.set(b1, "tenant-b", std)
	legacy := &fakeLegacy{byGateway: map[ids.GatewayID]int64{
		a1:     70, // tenant-a: 70 + 60 = 130 > 100, only because it had two gateways
		a2:     60,
		b1:     90, // tenant-b: 90 <= 100
		orphan: 5,  // a gateway that no longer resolves
	}}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	audit := NewRolloutAudit(r, legacy, "2026-10", logger)
	audit.now = func() time.Time { return midMonth }
	return audit, legacy, &buf
}

func TestRolloutAuditNamesTenantsWhosePerGatewayCountersAddedUpPastTheCap(t *testing.T) {
	t.Parallel()
	audit, _, logs := auditFixture(t)

	report, err := audit.Once(context.Background())
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "2026-10", report.Month)
	assert.Equal(t, []string{"tenant-a"}, report.OverQuotaTenants)
	assert.Equal(t, 4, report.LegacyKeys)
	assert.Equal(t, 2, report.Tenants)
	assert.Equal(t, 1, report.Unresolved)

	out := logs.String()
	assert.Contains(t, out, "tenant_id=tenant-a")
	assert.Contains(t, out, "used=130")
	assert.NotContains(t, out, "tenant_id=tenant-b", "a tenant under its cap is not reported")
	assert.True(t, strings.Contains(out, "level=WARN"))
}

// All the pods start together; only one may run the audit, or the report is
// logged N times.
func TestRolloutAuditRunsOncePerMonthAcrossPods(t *testing.T) {
	t.Parallel()
	audit, legacy, _ := auditFixture(t)

	first, err := audit.Once(context.Background())
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := audit.Once(context.Background())
	require.NoError(t, err)
	assert.Nil(t, second, "another pod already did it")
	assert.Len(t, legacy.taken, 1)
}

func TestRolloutAuditFailureIsReportedNotSwallowed(t *testing.T) {
	t.Parallel()
	audit, legacy, _ := auditFixture(t)
	legacy.err = errors.New("redis down")
	_, err := audit.Once(context.Background())
	require.Error(t, err)
}

func TestRolloutAuditRunWaitsForTheSnapshotAndStopsOnCancel(t *testing.T) {
	t.Parallel()
	audit, legacy, _ := auditFixture(t)
	audit.delay = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { audit.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
	assert.Empty(t, legacy.taken, "it never reached the audit")
}

// A scan that fails after the claim was taken must not silence the audit for
// everyone: the claim goes back, and the next pod or boot does the work.
func TestRolloutAuditGivesTheClaimBackWhenTheScanFails(t *testing.T) {
	t.Parallel()
	audit, legacy, _ := auditFixture(t)
	legacy.scanErr = errors.New("redis went away mid-scan")

	report, err := audit.Once(context.Background())
	require.Error(t, err)
	assert.Nil(t, report)
	assert.Empty(t, legacy.taken, "the claim was released")

	legacy.scanErr = nil
	retry, err := audit.Once(context.Background())
	require.NoError(t, err)
	require.NotNil(t, retry, "a later attempt gets to run it")
	assert.Equal(t, []string{"tenant-a"}, retry.OverQuotaTenants)
}

func TestRolloutAuditKeepsTheClaimAfterASuccess(t *testing.T) {
	t.Parallel()
	audit, legacy, _ := auditFixture(t)
	_, err := audit.Once(context.Background())
	require.NoError(t, err)
	assert.Len(t, legacy.taken, 1, "a finished audit stays claimed for the month")
}

// A failure to claim (Redis down) is not a claim: nothing to release.
func TestRolloutAuditOnlyRunsDuringTheRolloutMonth(t *testing.T) {
	t.Parallel()
	for name, month := range map[string]string{"disabled (empty)": "", "a past month": "2026-09", "a future month": "2026-11"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			audit, legacy, _ := auditFixture(t)
			audit.month = month

			report, err := audit.Once(context.Background())
			require.NoError(t, err)
			assert.Nil(t, report)
			assert.Empty(t, legacy.taken, "it did not even claim")
			assert.Zero(t, legacy.scanned)
		})
	}

	audit, legacy, _ := auditFixture(t)
	report, err := audit.Once(context.Background())
	require.NoError(t, err)
	require.NotNil(t, report, "the configured month is the current one")
	assert.Equal(t, 1, legacy.scanned)
}
