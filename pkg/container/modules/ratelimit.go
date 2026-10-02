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
	"log/slog"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	inforatelimit "github.com/NeuralTrust/TrustGate/pkg/infra/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/adapters"
	"go.uber.org/dig"
)

// rateLimitDeps is what the meter is built from. Exactly one of the two caps
// sources is present: Cache on a plane that reads Postgres (the Gateway module),
// Snapshot on a DB-less data plane (CoreData). Neither is present nowhere.
type rateLimitDeps struct {
	dig.In
	Cfg        *config.Config
	Finder     appgateway.Finder
	SyncClient *cache.SyncClient
	Logger     *slog.Logger
	Cache      *ratelimitapp.TenantCapsCache `optional:"true"`
	Snapshot   *adapters.TenantCapsSource    `optional:"true"`
}

// tierLoader reads the tenant's caps from whichever source this plane has. The
// source is never queried per request: the cache is a polled copy and the
// snapshot lives in memory.
func (p rateLimitDeps) tierLoader() ratelimitapp.GatewayTierLoader {
	switch {
	case p.Cache != nil:
		return ratelimitapp.NewGatewayTierLoader(p.Finder, p.Cache)
	case p.Snapshot != nil:
		return ratelimitapp.NewGatewayTierLoader(p.Finder, p.Snapshot)
	default:
		return ratelimitapp.NewGatewayTierLoader(p.Finder, nil)
	}
}

// RateLimit wires the plan limiter: an in-memory Meter that the proxy and MCP
// request paths charge, and the background sync that reconciles it with Redis
// through a client of its own. The request path holds no Redis client.
//
// With RATE_LIMIT_ENABLED=false the sync client is nil: nothing is built, not
// even the credentials provider (which for AWS IAM auth would resolve AWS
// credentials), so a disabled limiter costs the process nothing.
func RateLimit(c *container.Container) error {
	if err := c.Provide(func(cfg *config.Config) (*cache.SyncClient, error) {
		if !cfg.RateLimit.Enabled {
			return nil, nil
		}
		return cache.NewSyncClient(cache.Config{
			Login:             cfg.Redis.Login,
			Host:              cfg.Redis.Host,
			Port:              cfg.Redis.Port,
			Username:          cfg.Redis.Username,
			Password:          cfg.Redis.Password,
			DB:                cfg.Redis.DB,
			TLSEnabled:        cfg.Redis.TLSEnabled,
			TLSInsecureVerify: cfg.Redis.TLSInsecureVerify,
			CacheName:         cfg.Redis.CacheName,
			AWSServerless:     cfg.Redis.AWSServerless,
		}, cfg.RateLimit.SyncTimeout)
	}); err != nil {
		return err
	}
	// The meter is nil when plan rate limiting is off, so that nothing starts a
	// sync loop for a limiter that does nothing.
	if err := c.Provide(func(p rateLimitDeps) *ratelimitapp.Meter {
		if !p.Cfg.RateLimit.Enabled {
			return nil
		}
		return ratelimitapp.NewMeter(
			p.tierLoader(),
			inforatelimit.NewStore(p.SyncClient.Client, p.Logger,
				inforatelimit.WithFailedRetention(p.Cfg.RateLimit.FailedRetention)),
			ratelimitapp.Options{
				SyncInterval:    p.Cfg.RateLimit.SyncInterval,
				SyncTimeout:     p.Cfg.RateLimit.SyncTimeout,
				FailedRetention: p.Cfg.RateLimit.FailedRetention,
			},
			p.Logger,
		)
	}); err != nil {
		return err
	}
	return c.Provide(func(meter *ratelimitapp.Meter) ratelimitapp.Checker {
		if meter == nil {
			return ratelimitapp.NewNoopChecker()
		}
		return meter
	})
}
