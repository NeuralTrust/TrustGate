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

	configsnapshothandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"go.uber.org/dig"
)

type compilerReaders struct {
	dig.In
	Gateways   gatewaydomain.Repository
	Consumers  consumerdomain.Repository
	Registries registrydomain.Repository
	Policies   policydomain.Repository
	Auths      authdomain.Repository
	Roles      roledomain.Repository
	Catalog    catalogdomain.Repository
}

func ControlConfigSync(c *container.Container) error {
	if err := c.Provide(func(r compilerReaders, logger *slog.Logger) *appsnapshot.Compiler {
		return appsnapshot.NewCompiler(r.Gateways, r.Consumers, r.Registries, r.Policies, r.Auths, r.Roles, r.Catalog, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(appsnapshot.NewHolder); err != nil {
		return err
	}
	if err := c.Provide(func() configsync.SnapshotCodec[*readmodel.Snapshot] {
		return infrasnapshot.NewCodec()
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, cc cache.Client) configsync.ChangeNotifier {
		return configsync.NewRedisStreamNotifier(cc.RedisClient(), cfg.ConfigSync.StreamKey, cfg.ConfigSync.StreamMaxLen)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		compiler *appsnapshot.Compiler,
		codec configsync.SnapshotCodec[*readmodel.Snapshot],
		holder *appsnapshot.Holder,
		notifier configsync.ChangeNotifier,
		logger *slog.Logger,
		cfg *config.Config,
	) *appsnapshot.Recompiler {
		return appsnapshot.NewRecompiler(compiler, codec, holder, notifier, logger, appsnapshot.RecompilerConfig{
			Debounce: cfg.ConfigSync.RecompileDebounce,
			Backstop: cfg.ConfigSync.RecompileBackstop,
		})
	}); err != nil {
		return err
	}
	if err := c.Provide(func(r *appsnapshot.Recompiler) *appsnapshot.SnapshotVersionPublisher {
		return appsnapshot.NewSnapshotVersionPublisher(r)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(p *appsnapshot.SnapshotVersionPublisher) configsyncport.SnapshotSignaler {
		return p
	}); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewConfigSyncAuthMiddleware); err != nil {
		return err
	}
	return c.Provide(func(holder *appsnapshot.Holder, logger *slog.Logger) *configsnapshothandler.Handler {
		return configsnapshothandler.NewHandler(holder, logger)
	})
}
