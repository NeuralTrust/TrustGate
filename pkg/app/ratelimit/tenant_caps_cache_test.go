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
	"errors"
	"sync"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLister is Postgres: its rows can change and its reads can fail.
type fakeLister struct {
	mu    sync.Mutex
	rows  []domain.TenantCaps
	err   error
	calls int
}

func (f *fakeLister) ListTenantCaps(context.Context) ([]domain.TenantCaps, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return append([]domain.TenantCaps(nil), f.rows...), nil
}

func (f *fakeLister) set(rows []domain.TenantCaps, err error) {
	f.mu.Lock()
	f.rows, f.err = rows, err
	f.mu.Unlock()
}

func capsRow(tenant string, burst int) domain.TenantCaps {
	return domain.TenantCaps{TenantID: tenant, Tier: "standard", BurstPerMin: burst, QuotaPerMonth: 100_000, MaxInstances: 5}
}

func TestTenantCapsCacheNeverLoadedIsNotFound(t *testing.T) {
	t.Parallel()
	c := NewTenantCapsCache(&fakeLister{}, time.Hour, discardLogger())

	got, err := c.FindTenantCaps(context.Background(), "tenant-1")
	assert.Nil(t, got)
	assert.ErrorIs(t, err, commonerrors.ErrNotFound)
}

// The relation not existing yet (the control plane has not migrated) is a load
// error like any other: the answer stays "not found", never "no limit".
func TestTenantCapsCacheFailedFirstLoadStaysNotFound(t *testing.T) {
	t.Parallel()
	lister := &fakeLister{err: errors.New(`relation "tenant_entitlements" does not exist`)}
	c := NewTenantCapsCache(lister, time.Hour, discardLogger())

	require.Error(t, c.Load(context.Background()))
	_, err := c.FindTenantCaps(context.Background(), "tenant-1")
	assert.ErrorIs(t, err, commonerrors.ErrNotFound)
}

func TestTenantCapsCacheServesALoadedTenantAndNotFoundForTheRest(t *testing.T) {
	t.Parallel()
	lister := &fakeLister{rows: []domain.TenantCaps{capsRow("tenant-1", 300)}}
	c := NewTenantCapsCache(lister, time.Hour, discardLogger())
	require.NoError(t, c.Load(context.Background()))

	got, err := c.FindTenantCaps(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, capsRow("tenant-1", 300), *got)

	_, err = c.FindTenantCaps(context.Background(), "tenant-2")
	assert.ErrorIs(t, err, commonerrors.ErrNotFound)
}

func TestTenantCapsCacheRefreshPicksUpAChange(t *testing.T) {
	t.Parallel()
	lister := &fakeLister{rows: []domain.TenantCaps{capsRow("tenant-1", 60)}}
	c := NewTenantCapsCache(lister, 10*time.Millisecond, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, 2*time.Second, func() bool {
		got, err := c.FindTenantCaps(ctx, "tenant-1")
		return err == nil && got.BurstPerMin == 60
	}, "the first load runs as soon as the loop starts")

	lister.set([]domain.TenantCaps{capsRow("tenant-1", 1000), capsRow("tenant-2", 5)}, nil)
	waitFor(t, 2*time.Second, func() bool {
		got, err := c.FindTenantCaps(ctx, "tenant-1")
		_, err2 := c.FindTenantCaps(ctx, "tenant-2")
		return err == nil && got.BurstPerMin == 1000 && err2 == nil
	}, "a restamp and a new tenant show up on the next refresh")
}

// A cache that never loaded retries on a short backoff, not once per interval.
func TestTenantCapsCacheRetriesAFailedFirstLoadFasterThanTheInterval(t *testing.T) {
	t.Parallel()
	lister := &fakeLister{err: errors.New("postgres not up yet")}
	c := NewTenantCapsCache(lister, time.Hour, discardLogger())
	c.retryMin = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, 2*time.Second, func() bool {
		lister.mu.Lock()
		defer lister.mu.Unlock()
		return lister.calls >= 3
	}, "it keeps retrying while it has nothing")

	lister.set([]domain.TenantCaps{capsRow("tenant-1", 300)}, nil)
	waitFor(t, 2*time.Second, func() bool {
		_, err := c.FindTenantCaps(ctx, "tenant-1")
		return err == nil
	}, "and loads as soon as Postgres answers, long before the hourly refresh")
}

// After a failed Prime, Run does not repeat the attempt at once: the first retry
// waits retryMin.
func TestTenantCapsCacheRunWaitsBeforeRetryingAFailedPrime(t *testing.T) {
	t.Parallel()
	lister := &fakeLister{err: errors.New("postgres not up yet")}
	c := NewTenantCapsCache(lister, time.Hour, discardLogger())
	c.retryMin = 300 * time.Millisecond
	require.Error(t, c.Prime(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	calls := func() int {
		lister.mu.Lock()
		defer lister.mu.Unlock()
		return lister.calls
	}
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, calls(), "only the Prime attempt so far: Run is still waiting")
	waitFor(t, 2*time.Second, func() bool { return calls() >= 2 }, "and then it retries")
}

// A primed cache does not load again at the start of Run.
func TestTenantCapsCacheRunDoesNotReloadWhatPrimeLoaded(t *testing.T) {
	t.Parallel()
	lister := &fakeLister{rows: []domain.TenantCaps{capsRow("tenant-1", 300)}}
	c := NewTenantCapsCache(lister, time.Hour, discardLogger())
	require.NoError(t, c.Prime(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	lister.mu.Lock()
	defer lister.mu.Unlock()
	assert.Equal(t, 1, lister.calls)
}

type hangingLister struct{}

func (hangingLister) ListTenantCaps(ctx context.Context) ([]domain.TenantCaps, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestTenantCapsCachePrimeIsBounded(t *testing.T) {
	t.Parallel()
	c := NewTenantCapsCache(hangingLister{}, time.Hour, discardLogger())
	c.primeTimeout = 30 * time.Millisecond

	started := time.Now()
	require.Error(t, c.Prime(context.Background()))
	assert.Less(t, time.Since(started), 2*time.Second)
	_, err := c.FindTenantCaps(context.Background(), "tenant-1")
	assert.ErrorIs(t, err, commonerrors.ErrNotFound)
}

func TestTenantCapsCacheLoadErrorKeepsTheLastGoodMapAndCountsIt(t *testing.T) {
	read := captureMetrics(t)
	lister := &fakeLister{rows: []domain.TenantCaps{capsRow("tenant-1", 300)}}
	c := NewTenantCapsCache(lister, time.Hour, discardLogger())
	require.NoError(t, c.Load(context.Background()))

	lister.set(nil, errors.New("postgres down"))
	require.Error(t, c.Load(context.Background()))
	require.Error(t, c.Load(context.Background()))

	got, err := c.FindTenantCaps(context.Background(), "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, 300, got.BurstPerMin, "an outage does not unlimit or unknow the tenant")
	assert.EqualValues(t, 2, read("trustgate.ratelimit.tenant_caps.load_errors"))
}

func TestTenantCapsCacheReturnsACopy(t *testing.T) {
	t.Parallel()
	lister := &fakeLister{rows: []domain.TenantCaps{capsRow("tenant-1", 300)}}
	c := NewTenantCapsCache(lister, time.Hour, discardLogger())
	require.NoError(t, c.Load(context.Background()))

	got, _ := c.FindTenantCaps(context.Background(), "tenant-1")
	got.BurstPerMin = 1
	again, _ := c.FindTenantCaps(context.Background(), "tenant-1")
	assert.Equal(t, 300, again.BurstPerMin)
}
