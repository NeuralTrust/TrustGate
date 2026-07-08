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
	"fmt"
	"log/slog"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	configsyncgrpc "github.com/NeuralTrust/TrustGate/pkg/infra/configsync/grpc"
	configsyncconnrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
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

// ControlConfigSync registers the control-plane half of the gRPC-based config
// sync: the snapshot compiler over the live repositories, the atomic holder the
// gRPC server serves from, the protobuf codec, the connection hub that fans
// version notices out to connected data planes, the ConfigSync gRPC service and
// its TLS/auth-guarded server, the debounced dispatcher that compiles snapshots
// and drains the change-marker outbox, and the version-bump signaler the admin
// write use cases call. The dispatcher and gRPC server are started in the
// control/run run funcs; nothing here resolves on the data plane graph.
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
	if err := c.Provide(func(r *outboxrepo.Repository) configsyncport.OutboxRepository {
		return r
	}); err != nil {
		return err
	}
	if err := c.Provide(configsyncconnrepo.NewRepository); err != nil {
		return err
	}
	if err := c.Provide(func(r *configsyncconnrepo.Repository) configsyncgrpc.ConnectionStore {
		return r
	}); err != nil {
		return err
	}
	if err := c.Provide(func(logger *slog.Logger, store configsyncgrpc.ConnectionStore) *configsyncgrpc.Hub {
		return configsyncgrpc.NewHub(logger, store)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(hub *configsyncgrpc.Hub) configsyncport.VersionBroadcaster {
		return hub
	}); err != nil {
		return err
	}
	if err := c.Provide(func(hub *configsyncgrpc.Hub, holder *appsnapshot.Holder, logger *slog.Logger) *configsyncgrpc.Service {
		return configsyncgrpc.NewService(hub, holder, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(svc *configsyncgrpc.Service) snapshotpb.ConfigSyncServer {
		return svc
	}); err != nil {
		return err
	}
	if err := c.Provide(configsyncgrpc.NewAuthInterceptor); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, svc snapshotpb.ConfigSyncServer, auth *configsyncgrpc.AuthInterceptor, logger *slog.Logger) (*configsyncgrpc.Server, error) {
		if cfg.IsDeployed() && (cfg.ConfigSync.GRPCTLSCertPath == "" || cfg.ConfigSync.GRPCTLSKeyPath == "") {
			return nil, fmt.Errorf("%w: CONFIG_SYNC_GRPC_TLS_CERT and CONFIG_SYNC_GRPC_TLS_KEY are required on the control plane in deployed environments", commonerrors.ErrInvalidConfig)
		}
		return configsyncgrpc.NewServer(cfg.ConfigSync, svc, auth, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		compiler *appsnapshot.Compiler,
		codec configsync.SnapshotCodec[*readmodel.Snapshot],
		holder *appsnapshot.Holder,
		broadcaster configsyncport.VersionBroadcaster,
		outbox configsyncport.OutboxRepository,
		logger *slog.Logger,
		cfg *config.Config,
	) *appsnapshot.Dispatcher {
		return appsnapshot.NewDispatcher(compiler, codec, holder, broadcaster, outbox, logger, appsnapshot.DispatcherConfig{
			Debounce:  cfg.ConfigSync.RecompileDebounce,
			Backstop:  cfg.ConfigSync.RecompileBackstop,
			Retention: cfg.ConfigSync.OutboxRetention,
			MaxRows:   int(cfg.ConfigSync.OutboxMaxRows),
		})
	}); err != nil {
		return err
	}
	if err := c.Provide(func(d *appsnapshot.Dispatcher) *appsnapshot.SnapshotVersionPublisher {
		return appsnapshot.NewSnapshotVersionPublisher(d)
	}); err != nil {
		return err
	}
	return c.Provide(func(p *appsnapshot.SnapshotVersionPublisher) configsyncport.SnapshotSignaler {
		return p
	})
}
