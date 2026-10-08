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
	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/subscriber"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	configsyncgrpc "github.com/NeuralTrust/TrustGate/pkg/infra/configsync/grpc"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	lkgrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsnapshotlkg"
	configsyncconnrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"go.opentelemetry.io/otel"
	"go.uber.org/dig"
)

type compilerReaders struct {
	dig.In
	Gateways   gatewaydomain.Repository
	Consumers  consumerdomain.Repository
	Registries registrydomain.Repository
	Policies   policydomain.Repository
	Auths      authdomain.Repository
	Catalog    catalogdomain.Repository
	// Grants and Policies put the MCP Store access grants and per-principal
	// levels into every snapshot.
	Grants        storeaccessdomain.Repository
	StorePolicies storeaccessdomain.PolicyRepository
	// TenantCaps puts each tenant's plan caps into the snapshots that carry its
	// gateways.
	TenantCaps ratelimitdomain.TenantCapsRepository
	// PinnedTools puts the decided tool set of pinned MCP registries into the
	// snapshots. Deliberately not optional: without it a pinned registry would
	// publish with nothing approved and silently hide every tool.
	PinnedTools registrydomain.PinnedToolRepository
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
	if err := c.Provide(func(r compilerReaders, shared mcpoauth.Provider, cfg *config.Config, logger *slog.Logger) (*appsnapshot.Compiler, error) {
		keys, err := playgroundSnapshotKeys(cfg)
		if err != nil {
			return nil, err
		}
		return appsnapshot.NewCompiler(
			r.Gateways, r.Consumers, r.Registries, r.Policies, r.Auths, r.Catalog, logger,
			appsnapshot.WithStoreGrants(r.Grants),
			appsnapshot.WithStorePolicies(r.StorePolicies),
			appsnapshot.WithPlaygroundTokenKeys(keys),
			appsnapshot.WithTenantCaps(r.TenantCaps),
			appsnapshot.WithPinnedTools(r.PinnedTools),
			appsnapshot.WithSharedOAuth(shared),
		), nil
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
	if err := c.Provide(func(repo installationdomain.Repository, ensurer appstore.RegistryEnsurer, gateways gatewaydomain.Repository, logger *slog.Logger) snapshotpb.StoreInstallationsServer {
		return configsyncgrpc.NewInstallationsService(repo, ensurer, gateways, logger)
	}); err != nil {
		return err
	}
	// The DB-less data plane reports pending pinned tools over the same channel.
	// The service treats the caller as untrusted; see PinnedToolsService.
	if err := c.Provide(func(registries registrydomain.Repository, tools registrydomain.PinnedToolRepository, gateways gatewaydomain.Repository, logger *slog.Logger) snapshotpb.PinnedToolsServer {
		return configsyncgrpc.NewPinnedToolsService(registries, tools, gateways, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(configsyncgrpc.NewAuthInterceptor); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, svc snapshotpb.ConfigSyncServer, installations snapshotpb.StoreInstallationsServer, pinned snapshotpb.PinnedToolsServer, auth *configsyncgrpc.AuthInterceptor, logger *slog.Logger) (*configsyncgrpc.Server, error) {
		if cfg.IsDeployed() && (cfg.ConfigSync.GRPCTLSCertPath == "" || cfg.ConfigSync.GRPCTLSKeyPath == "") {
			return nil, fmt.Errorf("%w: CONFIG_SYNC_GRPC_TLS_CERT and CONFIG_SYNC_GRPC_TLS_KEY are required on the control plane in deployed environments", commonerrors.ErrInvalidConfig)
		}
		return configsyncgrpc.NewServer(cfg.ConfigSync, svc, installations, auth, logger, configsyncgrpc.RegisterPinnedTools(pinned))
	}); err != nil {
		return err
	}
	if err := c.Provide(lkgrepo.NewRepository); err != nil {
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
		store *lkgrepo.Repository,
		// The encrypter is resolved first: in prod it provisions the shared
		// SERVER_SECRET_KEY into cfg, which the LKG key is derived from.
		_ vaultdomain.Encrypter,
		// The SDK installs the global MeterProvider the gauges register on.
		_ *o11y.SDK,
	) (*appsnapshot.Dispatcher, error) {
		var opts []appsnapshot.DispatcherOption
		if cfg.ConfigSync.AdminLKGEnabled {
			sealer, err := infrasnapshot.NewLKGSealer(cfg.Server.SecretKey)
			if err != nil {
				// Without a usable secret the feature cannot encrypt; the admin
				// keeps today's behaviour rather than failing to boot.
				logger.Warn("admin last-good snapshot disabled: no usable SERVER_SECRET_KEY",
					slog.String("component", "configsnapshot"), slog.String("error", err.Error()))
			} else {
				opts = append(opts, appsnapshot.WithLKG(store, sealer, appsnapshot.LKGConfig{MaxAge: cfg.ConfigSync.AdminLKGMaxAge}))
			}
		}
		d := appsnapshot.NewDispatcher(compiler, codec, holder, broadcaster, outbox, logger, appsnapshot.DispatcherConfig{
			Debounce:  cfg.ConfigSync.RecompileDebounce,
			Backstop:  cfg.ConfigSync.RecompileBackstop,
			Retention: cfg.ConfigSync.OutboxRetention,
			MaxRows:   int(cfg.ConfigSync.OutboxMaxRows),
		}, opts...)
		if err := appsnapshot.RegisterAdminSnapshotGauges(otel.Meter("trustgate/configsync"), d); err != nil {
			return nil, err
		}
		return d, nil
	}); err != nil {
		return err
	}
	if err := c.Provide(func(d *appsnapshot.Dispatcher) *appsnapshot.SnapshotVersionPublisher {
		return appsnapshot.NewSnapshotVersionPublisher(d)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(p *appsnapshot.SnapshotVersionPublisher, publisher cache.EventPublisher, logger *slog.Logger) configsyncport.SnapshotSignaler {
		return infrasnapshot.NewDistributedSignaler(p, publisher, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(d *appsnapshot.Dispatcher) subscriber.SnapshotSignaler {
		return d
	}); err != nil {
		return err
	}
	return c.Provide(subscriber.NewSnapshotDirtyEventSubscriber)
}

// playgroundSnapshotKeys turns the configured playground verification keys into
// the snapshot entries every compiled snapshot carries, with PEMs normalized so
// data planes parse them as-is. Parsing here fails boot on a malformed key
// rather than shipping a key no data plane can use.
func playgroundSnapshotKeys(cfg *config.Config) ([]readmodel.VerificationKey, error) {
	entries := cfg.Playground.TokenPublicKeys
	if len(entries) == 0 {
		return nil, nil
	}
	if _, err := jwt.StaticPlaygroundKeys(entries); err != nil {
		return nil, err
	}
	keys := make([]readmodel.VerificationKey, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, readmodel.VerificationKey{
			KID: entry.KID,
			PEM: jwt.NormalizeVerificationPEM(entry.PEM),
		})
	}
	return keys, nil
}
