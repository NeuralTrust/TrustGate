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

package modules

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/dig"
)

type emptyStateCache struct{}

func (emptyStateCache) SaveAll(context.Context, []usagedomain.TenantState) error   { return nil }
func (emptyStateCache) LoadAll(context.Context) ([]usagedomain.TenantState, error) { return nil, nil }

func enabledUsage() config.UsageConfig {
	return config.UsageConfig{
		Enabled:                true,
		ReadyTimeout:           time.Hour,
		GRPCKeepaliveTime:      30 * time.Second,
		GRPCKeepaliveTimeout:   10 * time.Second,
		GRPCMaxMessageBytes:    64 << 20,
		ReconnectMinBackoff:    time.Second,
		ReconnectMaxBackoff:    time.Second,
		CacheRestoreInterval:   time.Millisecond,
		CacheRestoreMaxBackoff: time.Millisecond,
		CacheWriteTimeout:      time.Second,
		CacheRetryInterval:     time.Millisecond,
	}
}

func TestAdminUsageReadinessFollowsTheFlag(t *testing.T) {
	t.Parallel()
	for _, enabled := range []bool{false, true} {
		for _, plane := range []string{"admin", "proxy"} {
			c, err := container.New(container.WithModule(adminReadiness(plane)))
			require.NoError(t, err)
			require.NoError(t, c.Provide(func() *appsnapshot.Dispatcher { return &appsnapshot.Dispatcher{} }))
			require.NoError(t, c.Provide(func() *config.Config {
				return &config.Config{Usage: config.UsageConfig{Enabled: enabled, ReadyTimeout: time.Hour}}
			}))
			require.NoError(t, c.Provide(func() *slog.Logger { return slog.Default() }))
			store := appusage.NewStore(emptyStateCache{}, nil, time.Second)
			require.NoError(t, c.Provide(func() appusage.Reader { return store }))

			var check adminUsageReadiness
			require.NoError(t, c.Invoke(func(p struct {
				dig.In
				Check adminUsageReadiness `optional:"true"`
			}) {
				check = p.Check
			}))
			if !enabled || plane != "admin" {
				assert.Nil(t, check, "plane %s enabled %v", plane, enabled)
				continue
			}
			require.NotNil(t, check)
			assert.ErrorIs(t, check(context.Background()), appusage.ErrListNotReady)
			require.NoError(t, store.Restore(context.Background(), false))
			assert.NoError(t, check(context.Background()))
		}
	}
}

func TestDataPlaneUsageReadinessFollowsTheSnapshotFlag(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Usage: config.UsageConfig{ReadyTimeout: time.Hour}}
	withFlag := func(enforced bool) configsync.ConfigStore[*readmodel.Snapshot] {
		store := configsync.NewMemoryStore[*readmodel.Snapshot]()
		store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: readmodel.Build(readmodel.Data{UsageEnforcement: enforced})})
		return store
	}

	off := dataPlaneUsageReadiness(withFlag(false), appusage.NewEnforcement(), cfg, slog.Default())
	assert.NoError(t, off(context.Background()), "flag off must not wait for a usage list")

	enforcement := appusage.NewEnforcement()
	on := dataPlaneUsageReadiness(withFlag(true), enforcement, cfg, slog.Default())
	assert.ErrorIs(t, on(context.Background()), appusage.ErrListNotReady)
	enforcement.ApplySnapshot(usagedomain.Snapshot{})
	assert.NoError(t, on(context.Background()))
}

func TestUsageSyncClientOnlyWithEnabledAndAddress(t *testing.T) {
	t.Parallel()
	store := appusage.NewStore(emptyStateCache{}, nil, time.Second)
	withAddr := func(addr string) config.UsageConfig {
		usage := enabledUsage()
		usage.GRPCAddr = addr
		usage.GRPCInsecure = true
		return usage
	}
	for _, tc := range []struct {
		usage   config.UsageConfig
		want    bool
		wantErr bool
	}{
		{usage: config.UsageConfig{}, want: false},
		{usage: enabledUsage(), want: false},
		{usage: config.UsageConfig{GRPCAddr: "usage-system:9090"}, want: false},
		{usage: withAddr("usage-system:9090"), want: true},
		{usage: withAddr("usage-system"), wantErr: true},
	} {
		client, err := provideUsageSyncClient(&config.Config{Usage: tc.usage}, store, slog.Default())
		if tc.wantErr {
			require.Error(t, err, "%+v", tc.usage)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, client != nil, "%+v", tc.usage)
		if client != nil {
			require.NoError(t, client.Close())
		}
	}
}

func TestUsageForPlane(t *testing.T) {
	t.Parallel()
	state, err := usagedomain.NewTenantState("tenant-a", usagedomain.StatusExhausted, usagedomain.ReasonWalletEmpty, 2)
	require.NoError(t, err)
	for _, tc := range []struct {
		plane     string
		enabled   bool
		wantLocal bool
		wantLog   bool
	}{
		{plane: "run", enabled: true, wantLocal: true},
		{plane: "admin", enabled: true},
		{plane: "proxy", enabled: true, wantLog: true},
		{plane: "mcp", enabled: true, wantLog: true},
		{plane: "proxy", enabled: false},
		{plane: "proxi", enabled: true, wantLog: true},
	} {
		var logs bytes.Buffer
		usage := enabledUsage()
		usage.Enabled = tc.enabled
		c, err := container.New(container.WithModule(usageForPlane(tc.plane)))
		require.NoError(t, err)
		require.NoError(t, c.Provide(func() *config.Config { return &config.Config{Usage: usage} }))
		require.NoError(t, c.Provide(func() *slog.Logger { return slog.New(slog.NewTextHandler(&logs, nil)) }))
		store := appusage.NewStore(emptyStateCache{}, nil, time.Second)
		require.NoError(t, store.Apply(context.Background(), []usagedomain.TenantState{state}))
		require.NoError(t, c.Provide(func() *appusage.Store { return store }))
		require.NoError(t, c.Provide(provideUsageGuard))

		require.NoError(t, c.Invoke(func(p struct {
			dig.In
			Guard *middleware.UsageGuardMiddleware
			Local *localUsage `optional:"true"`
		}) {
			require.NotNil(t, p.Guard)
			assert.Equal(t, tc.wantLocal, p.Local != nil, "plane %s", tc.plane)
			if p.Local != nil {
				_, exhausted := p.Local.checker.Exhausted("tenant-a")
				assert.True(t, exhausted && p.Local.enabled(), "the run plane blocks from its own store")
			}
		}))
		assert.Equal(t, tc.wantLog, bytes.Contains(logs.Bytes(), []byte("no usage list")), "plane %s enabled %v: %s", tc.plane, tc.enabled, logs.String())
	}
}

func TestUsageLoopsRestoreAndStop(t *testing.T) {
	t.Parallel()
	var disabled *UsageLoops
	disabled.Start()
	disabled.Stop()
	assert.Nil(t, provideUsageLoops(&config.Config{}, nil, nil, slog.Default()))

	store := appusage.NewStore(emptyStateCache{}, nil, time.Second)
	loops := provideUsageLoops(&config.Config{Usage: enabledUsage()}, store, nil, slog.Default())
	loops.Start()
	require.Eventually(t, store.Ready, 2*time.Second, 5*time.Millisecond, "without a UsageSync stream an empty cache makes the store ready")
	loops.Stop()
}

type flakyStateCache struct {
	mu       sync.Mutex
	failures int
	saved    []usagedomain.TenantState
}

func (f *flakyStateCache) SaveAll(_ context.Context, states []usagedomain.TenantState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures > 0 {
		f.failures--
		return errors.New("redis down")
	}
	f.saved = append(f.saved, states...)
	return nil
}

func (f *flakyStateCache) LoadAll(context.Context) ([]usagedomain.TenantState, error) {
	return nil, nil
}

func (f *flakyStateCache) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.saved)
}

func TestUsageLoopsRetryFailedCacheWrites(t *testing.T) {
	t.Parallel()
	cache := &flakyStateCache{failures: 2}
	store := appusage.NewStore(cache, nil, time.Second)
	loops := provideUsageLoops(&config.Config{Usage: enabledUsage()}, store, nil, slog.Default())
	loops.Start()
	defer loops.Stop()

	state, err := usagedomain.NewTenantState("tenant-a", usagedomain.StatusExhausted, usagedomain.ReasonWalletEmpty, 2)
	require.NoError(t, err)
	require.NoError(t, store.Apply(context.Background(), []usagedomain.TenantState{state}))
	require.Eventually(t, func() bool { return cache.count() == 1 }, 2*time.Second, 5*time.Millisecond, "the failed write was never retried")
}
