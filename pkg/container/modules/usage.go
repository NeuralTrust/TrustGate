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
	"time"

	appusage "github.com/NeuralTrust/TrustGate/pkg/app/usage"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrausage "github.com/NeuralTrust/TrustGate/pkg/infra/usage"
	"go.uber.org/dig"
)

const usageRestoreRetry = 2 * time.Second

// Usage registers the control plane's usage state store and its Redis cache.
// Nothing here runs unless USAGE_SYSTEM_ENABLED is set.
func Usage(c *container.Container) error {
	if err := c.Provide(func(client cache.Client) usagedomain.StateCache {
		return infrausage.NewRedisStateCache(client.RedisClient())
	}); err != nil {
		return err
	}
	if err := c.Provide(appusage.NewStore); err != nil {
		return err
	}
	if err := c.Provide(func(s *appusage.Store) appusage.Applier { return s }); err != nil {
		return err
	}
	return c.Provide(func(s *appusage.Store) appusage.Reader { return s })
}

// UsageRestoreParams are the dependencies of StartUsageRestore.
type UsageRestoreParams struct {
	dig.In
	Cfg    *config.Config
	Store  *appusage.Store
	Logger *slog.Logger
}

// StartUsageRestore loads the cached usage states in the background, retrying
// until it succeeds, so a control plane that starts while Usage System is
// unreachable still serves the last known list.
func StartUsageRestore(p UsageRestoreParams) {
	if !p.Cfg.Usage.Enabled {
		return
	}
	go p.Store.RestoreUntilReady(context.Background(), usageRestoreRetry)
}

type adminUsageReadiness func(context.Context) error

func provideAdminUsageReadiness(cfg *config.Config, reader appusage.Reader, logger *slog.Logger) adminUsageReadiness {
	if !cfg.Usage.Enabled {
		return nil
	}
	return appusage.ReadinessCheck(reader.Ready, cfg.Usage.ReadyTimeout, logger)
}
