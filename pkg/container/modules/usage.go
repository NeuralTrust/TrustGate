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
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrausage "github.com/NeuralTrust/TrustGate/pkg/infra/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/usagesync"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"go.uber.org/dig"
)

// Usage registers the control plane's usage state store and its Redis cache.
// Nothing here runs unless USAGE_SYSTEM_ENABLED is set.
func Usage(c *container.Container) error {
	for _, provider := range []any{
		func(client cache.Client) usagedomain.StateCache {
			return infrausage.NewRedisStateCache(client.RedisClient())
		},
		provideUsageStore,
		func(s *appusage.Store) appusage.Applier { return s },
		func(s *appusage.Store) appusage.Reader { return s },
		provideUsageSyncClient,
		provideUsageLoops,
	} {
		if err := c.Provide(provider); err != nil {
			return err
		}
	}
	return nil
}

func provideUsageStore(cache usagedomain.StateCache, cfg *config.Config, logger *slog.Logger) *appusage.Store {
	return appusage.NewStore(cache, logger, cfg.Usage.CacheWriteTimeout)
}

// provideUsageSyncClient returns nil without an address: the control plane
// then serves the states cached in Redis only.
func provideUsageSyncClient(cfg *config.Config, store *appusage.Store, logger *slog.Logger) (*usagesync.Client, error) {
	if !cfg.Usage.Enabled {
		return nil, nil
	}
	if err := cfg.Usage.Validate(); err != nil {
		return nil, err
	}
	if cfg.Usage.GRPCAddr == "" {
		return nil, nil
	}
	return usagesync.NewClient(cfg.Usage, store, logger)
}

// UsageLoops runs the control plane's usage loops in the background: the
// Redis restore and, when Usage System's address is set, the UsageSync
// stream. Each control plane replica holds its own stream, so a change
// reaches every replica without cross-replica pub/sub. Its methods do nothing
// on a nil UsageLoops, which is what a disabled Usage System provides.
type UsageLoops struct {
	cfg    config.UsageConfig
	store  *appusage.Store
	client *usagesync.Client
	logger *slog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func provideUsageLoops(cfg *config.Config, store *appusage.Store, client *usagesync.Client, logger *slog.Logger) *UsageLoops {
	if !cfg.Usage.Enabled {
		return nil
	}
	return &UsageLoops{cfg: cfg.Usage, store: store, client: client, logger: logger}
}

// Start launches the loops, including the one that writes again the states a
// failed Redis write left behind.
func (l *UsageLoops) Start() {
	if l == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.store.RestoreUntilReady(ctx, appusage.RestoreOptions{
			Interval:   l.cfg.CacheRestoreInterval,
			MaxBackoff: l.cfg.CacheRestoreMaxBackoff,
			AwaitSync:  l.client != nil,
		})
	}()
	if l.client != nil {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.client.Run(ctx)
		}()
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		ticker := time.NewTicker(l.cfg.CacheRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.store.FlushPending(ctx)
			}
		}
	}()
}

// Stop ends the loops, waits for them, makes one last bounded attempt at the
// states a failed write left behind, and closes the UsageSync connection.
// Call it before Redis closes: all of this writes to it.
func (l *UsageLoops) Stop() {
	if l == nil || l.cancel == nil {
		return
	}
	l.cancel()
	l.wg.Wait()
	l.store.FlushPending(context.Background())
	if l.client != nil {
		if err := l.client.Close(); err != nil {
			l.logger.Warn("usagesync shutdown error", slog.String("error", err.Error()))
		}
	}
}

type adminUsageReadiness func(context.Context) error

func provideAdminUsageReadiness(cfg *config.Config, reader appusage.Reader, logger *slog.Logger) adminUsageReadiness {
	if !cfg.Usage.Enabled {
		return nil
	}
	return appusage.ReadinessCheck(reader.Ready, cfg.Usage.ReadyTimeout, logger)
}

// localUsage is the guard source of the run plane, which holds the usage
// store itself instead of receiving the list from a control plane.
type localUsage struct {
	checker appusage.ExhaustionChecker
	enabled func() bool
}

// postgresDataPlane marks a data plane backed by Postgres: no control plane
// feeds it usage states, so it cannot enforce them.
type postgresDataPlane bool

// usageForPlane wires what a non DB-less plane does with usage beyond the
// admin readiness: run blocks from its own store, admin serves no gateway
// traffic, and every other plane is a Postgres-backed data plane (main runs
// an unknown plane name as proxy), marked so its guard says it cannot enforce.
func usageForPlane(plane string) container.Module {
	return func(c *container.Container) error {
		switch plane {
		case PlaneRun:
			return c.Provide(provideLocalUsage)
		case PlaneAdmin:
			return nil
		default:
			return c.Provide(func() postgresDataPlane { return true })
		}
	}
}

func provideLocalUsage(cfg *config.Config, store *appusage.Store) *localUsage {
	enabled := cfg.Usage.Enabled
	return &localUsage{checker: store, enabled: func() bool { return enabled }}
}

type usageGuardParams struct {
	dig.In
	Cfg         *config.Config
	Logger      *slog.Logger
	Enforcement *appusage.Enforcement                       `optional:"true"`
	Snapshots   configsync.ConfigStore[*readmodel.Snapshot] `optional:"true"`
	Local       *localUsage                                 `optional:"true"`
	Postgres    postgresDataPlane                           `optional:"true"`
}

// provideUsageGuard reads a DB-less data plane's list, under the control
// plane's flag, or the run plane's own store. The admin plane serves no
// gateway traffic, and a Postgres-backed data plane has no list: it logs at
// boot when it is asked to enforce, so the gap is never silent.
func provideUsageGuard(p usageGuardParams) *middleware.UsageGuardMiddleware {
	switch {
	case p.Enforcement != nil && p.Snapshots != nil:
		return middleware.NewUsageGuardMiddleware(p.Enforcement, usageEnforcementFlag(p.Snapshots))
	case p.Local != nil:
		return middleware.NewUsageGuardMiddleware(p.Local.checker, p.Local.enabled)
	}
	if bool(p.Postgres) && p.Cfg.Usage.Enabled {
		p.Logger.Error("usage: a data plane backed by Postgres has no usage list and serves exhausted tenants; enforce usage with DB-less data planes")
	}
	return middleware.NewUsageGuardMiddleware(nil, nil)
}

func provideDataPlaneUsage(c *container.Container) error {
	if err := c.Provide(appusage.NewEnforcement); err != nil {
		return err
	}
	return c.Provide(func(e *appusage.Enforcement) appusage.ExhaustionChecker { return e })
}

func usageEnforcementFlag(store configsync.ConfigStore[*readmodel.Snapshot]) func() bool {
	return func() bool {
		current, ok := store.Load()
		return ok && current.Snapshot != nil && current.Snapshot.UsageEnforcement()
	}
}

func dataPlaneUsageReadiness(store configsync.ConfigStore[*readmodel.Snapshot], enforcement *appusage.Enforcement, cfg *config.Config, logger *slog.Logger) func(context.Context) error {
	enforced := usageEnforcementFlag(store)
	return appusage.ReadinessCheck(func() bool {
		return !enforced() || enforcement.Received()
	}, cfg.Usage.ReadyTimeout, logger)
}
