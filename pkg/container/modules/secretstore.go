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
	"sync/atomic"

	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"

	secretstorehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/secretstore"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	configsyncconnrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"

	"go.uber.org/dig"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/backends"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/localfile"
)

// SecretStores is what a plane runs to resolve secret references. Catalog
// and Cache are nil unless the plane loads a store file; the materializer
// always exists, so a reference that reaches a plane without stores is left
// empty instead of being forwarded.
type SecretStores struct {
	Catalog      *localfile.Catalog
	Cache        *appsecretref.Cache
	Materializer appsecretref.Materializer
	// Prewarmer resolves the plane's references in the background; nil
	// where Cache is.
	Prewarmer *appsecretref.Prewarmer
	logger    *slog.Logger

	cancel     context.CancelFunc
	wg         sync.WaitGroup
	prewarming atomic.Bool
}

type secretStoresParams struct {
	dig.In
	Config     *config.Config
	Gateways   gatewaydomain.Repository
	Registries registrydomain.Repository
	Manager    *cache.TTLMapManager
	Logger     *slog.Logger
}

// SecretStoresModule provides the plane's secret stores.
func SecretStoresModule(c *container.Container) error {
	if err := c.Provide(provideSecretStores); err != nil {
		return err
	}
	if err := c.Provide(provideSecretStoreTester); err != nil {
		return err
	}
	if err := c.Provide(func(s *SecretStores) appsecretref.Materializer { return s.Materializer }); err != nil {
		return err
	}
	return c.Provide(func(f appregistry.Finder, m appsecretref.Materializer) appregistry.RuntimeFinder {
		return appregistry.NewRuntimeFinder(f, m)
	})
}

// runtimeRegistries resolves the references of registries read by id
// alone, for readers that call the upstream outside a gateway's runtime
// data, such as the traffic-label classifier.
type runtimeRegistries struct {
	repo registrydomain.Repository
	m    appsecretref.Materializer
}

func (r runtimeRegistries) FindByID(ctx context.Context, id ids.RegistryID) (*registrydomain.Registry, error) {
	reg, err := r.repo.FindByID(ctx, id)
	if err != nil || r.m == nil {
		return reg, err
	}
	return r.m.Registries(ctx, reg.GatewayID, map[ids.RegistryID]*registrydomain.Registry{id: reg})[id], nil
}

func provideSecretStores(p secretStoresParams) (*SecretStores, error) {
	cfg := p.Config.SecretStores
	s := &SecretStores{logger: p.Logger}
	if cfg.File != "" {
		catalog, err := localfile.Open(cfg.File, backends.Factory(context.Background()), localfile.Options{
			DeploymentType: p.Config.ConfigSync.DeploymentType,
			Logger:         p.Logger,
			OnReload:       s.storesChanged,
		})
		if err != nil {
			return nil, err
		}
		s.Catalog = catalog
		s.Cache = appsecretref.NewCache(catalog, appsecretref.Options{
			FetchTimeout:    cfg.FetchTimeout,
			RefreshInterval: cfg.RefreshInterval,
			ProbeInterval:   cfg.ProbeInterval,
			Logger:          p.Logger,
		})
	}
	matCfg := appsecretref.MaterializerConfig{
		Eligibility: cfg.Gateways,
		Gateways:    p.Gateways,
		Invalidate:  appconsumer.InvalidateGatewayData(p.Manager),
		Logger:      p.Logger,
	}
	if s.Cache != nil {
		matCfg.Catalog, matCfg.Resolver = s.Catalog, s.Cache
	}
	s.Materializer = appsecretref.NewMaterializer(matCfg)
	if s.Cache != nil {
		s.Prewarmer = appsecretref.NewPrewarmer(appsecretref.PrewarmConfig{
			Catalog:     s.Catalog,
			Resolver:    s.Cache,
			Eligibility: cfg.Gateways,
			Gateways:    p.Gateways,
			Registries:  p.Registries,
			Logger:      p.Logger,
		})
	}
	if s.Catalog != nil {
		p.Logger.Info("secret stores loaded", slog.Int("stores", len(s.Catalog.Stores())), slog.String("eligibility", string(cfg.Gateways)))
	}
	return s, nil
}

// provideSecretStoreTester serves the admin test and the data-plane
// diagnostics route alike, against this plane's own catalog.
func provideSecretStoreTester(cfg *config.Config, stores *SecretStores, gateways gatewaydomain.Repository) appsecretstore.Tester {
	tc := appsecretstore.TesterConfig{
		Eligibility: cfg.SecretStores.Gateways,
		Gateways:    gateways,
		Timeout:     cfg.SecretStores.FetchTimeout,
	}
	if stores.Catalog != nil {
		tc.Catalog = stores.Catalog
	}
	return appsecretstore.NewTester(tc)
}

// storesChanged drops what was read from stores the store file added,
// changed or removed, and rebuilds the gateways that referenced them.
func (s *SecretStores) storesChanged(names []string) {
	if s.Cache != nil {
		for _, name := range names {
			s.Cache.InvalidateStore(name)
		}
	}
	if s.Materializer != nil {
		s.Materializer.StoresChanged(names)
	}
	s.Prewarm()
}

// Prewarm asks for a background pass over the plane's references; a no-op
// on a plane without stores or that does not serve traffic.
func (s *SecretStores) Prewarm() {
	if s != nil && s.Prewarmer != nil && s.prewarming.Load() {
		s.Prewarmer.Trigger()
	}
}

// StartServing is Start for a plane that serves traffic: it also prewarms
// the plane's references, now and after every snapshot apply and store-file
// reload. The admin only starts, so it never reads secrets it does not use.
func (s *SecretStores) StartServing() {
	s.start(true)
}

// Start runs the refresh and probe loops and the store file watch, when the
// plane loads a store file. Stop ends them.
func (s *SecretStores) Start() {
	s.start(false)
}

func (s *SecretStores) start(prewarm bool) {
	if s == nil || s.Cache == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.Cache.Run(ctx)
	}()
	go func() {
		defer s.wg.Done()
		if err := s.Catalog.Watch(ctx); err != nil {
			s.logger.Error("secret store file watch stopped; changes need a restart", slog.String("error", err.Error()))
		}
	}()
	if !prewarm {
		return
	}
	s.prewarming.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.Prewarmer.Run(ctx)
	}()
	s.Prewarm()
}

// Stop ends the loops Start began and waits for them.
func (s *SecretStores) Stop() {
	if s == nil || s.cancel == nil {
		return
	}
	s.cancel()
	s.wg.Wait()
}

// provideSecretStoresAdmin wires the control plane's side of secret stores:
// each gateway's store source, usages, the registry write validator and
// the admin routes. Only the full module set has the connection store it
// reads data-plane reports from.
func provideSecretStoresAdmin(c *container.Container) error {
	if err := c.Provide(func(cfg *config.Config, stores *SecretStores, conns *configsyncconnrepo.Repository) appsecretstore.SourceResolver {
		var health appsecretstore.StoreHealth
		if stores.Cache != nil {
			health = stores.Cache
		}
		return appsecretstore.NewSourceResolver(appsecretstore.SourceConfig{
			Eligibility:   cfg.SecretStores.Gateways,
			Health:        health,
			Instances:     conns,
			AdminInstance: cfg.ConfigSync.InstanceID,
		})
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo registrydomain.Repository) appsecretstore.UsagesFinder {
		return appsecretstore.NewUsagesFinder(repo)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, sources appsecretstore.SourceResolver, gateways gatewaydomain.Repository, logger *slog.Logger) appsecretstore.RegistryValidator {
		return appsecretstore.NewRegistryValidator(sources, gateways, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(gateways gatewaydomain.Repository, sources appsecretstore.SourceResolver, usages appsecretstore.UsagesFinder) *secretstorehttp.ListHandler {
		return secretstorehttp.NewListHandler(gateways, sources, usages)
	}); err != nil {
		return err
	}
	return c.Provide(func(gateways gatewaydomain.Repository, sources appsecretstore.SourceResolver, tester appsecretstore.Tester) *secretstorehttp.TestHandler {
		return secretstorehttp.NewTestHandler(gateways, sources, tester)
	})
}

// secretRefsParams is the write-time validator of secret references, absent
// on planes without the control plane's connection store.
type secretRefsParams struct {
	dig.In
	Validator appsecretstore.RegistryValidator `optional:"true"`
}

// entity returns the validator as the use cases take it, or nil.
func (p secretRefsParams) entity() appsecretref.EntityValidator {
	if p.Validator == nil {
		return nil
	}
	return p.Validator
}

func (p secretRefsParams) consumerOptions() []appconsumer.SaveOption {
	if v := p.entity(); v != nil {
		return []appconsumer.SaveOption{appconsumer.WithSecretRefValidator(v)}
	}
	return nil
}

func (p secretRefsParams) policyOptions() []apppolicy.SaveOption {
	if v := p.entity(); v != nil {
		return []apppolicy.SaveOption{apppolicy.WithSecretRefValidator(v)}
	}
	return nil
}
