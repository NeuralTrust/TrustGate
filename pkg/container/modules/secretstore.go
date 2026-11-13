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

	"go.uber.org/dig"

	secretstorehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/secretstore"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	secretstoredomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	configsyncconnrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"
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

	invalidateMu sync.Mutex
	invalidators []func(ids.GatewayID)
}

type secretStoresParams struct {
	dig.In
	Config     *config.Config
	Gateways   gatewaydomain.Repository
	Registries registrydomain.Repository
	Manager    *cache.TTLMapManager
	Logger     *slog.Logger
	Entities   SecretEntityListers
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
	s := &SecretStores{logger: p.Logger, invalidators: []func(ids.GatewayID){appconsumer.InvalidateGatewayData(p.Manager)}}
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
		Invalidate:  s.invalidate,
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
			Entities:    p.Entities.prewarm(),
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
		var refs func() secretstoredomain.RefHealth
		if stores.Cache != nil {
			health = stores.Cache
			refs = stores.Materializer.Health
		}
		return appsecretstore.NewSourceResolver(appsecretstore.SourceConfig{
			Eligibility:   cfg.SecretStores.Gateways,
			Health:        health,
			RefHealth:     refs,
			Instances:     conns,
			AdminInstance: cfg.ConfigSync.InstanceID,
		})
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo registrydomain.Repository, entities SecretEntityListers) appsecretstore.UsagesFinder {
		return appsecretstore.NewUsagesFinder(repo, entities.Listers()...)
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

// SecretEntityListers reads, as references, the entities besides registries
// that may hold one.
// A plane without one of them lists the others.
type SecretEntityListers struct {
	dig.In
	Consumers consumerdomain.Repository `optional:"true"`
	Policies  policydomain.Repository   `optional:"true"`
	Auths     authdomain.Repository     `optional:"true"`
	Gateways  gatewaydomain.Repository  `optional:"true"`
	Plugins   appplugins.Registry       `optional:"true"`
}

// Listers returns a lister for every entity the plane can read.
func (p SecretEntityListers) Listers() []appsecretstore.EntityLister {
	var out []appsecretstore.EntityLister
	if p.Gateways != nil {
		out = append(out, appsecretstore.GatewayReaderLister(p.Gateways))
	}
	if p.Consumers != nil {
		out = append(out, appsecretstore.ConsumerLister(p.Consumers))
	}
	if p.Policies != nil {
		out = append(out, appsecretstore.PolicyLister(p.Policies, func(pol *policydomain.Policy) appsecretref.EntityRefs {
			return apppolicy.SecretRefs(p.Plugins, pol)
		}))
	}
	if p.Auths != nil {
		out = append(out, appsecretstore.AuthLister(p.Auths))
	}
	return out
}

// SecretScanListers is SecretEntityListers with every source required: the
// pre-upgrade scan must fail to start, never report clean, when it cannot
// read an entity.
type SecretScanListers struct {
	dig.In
	Consumers consumerdomain.Repository
	Policies  policydomain.Repository
	Auths     authdomain.Repository
	Gateways  gatewaydomain.Repository
	Plugins   appplugins.Registry
}

// Listers returns a lister for every entity besides registries.
func (p SecretScanListers) Listers() []appsecretstore.EntityLister {
	return SecretEntityListers{
		Consumers: p.Consumers, Policies: p.Policies, Auths: p.Auths, Gateways: p.Gateways, Plugins: p.Plugins,
	}.Listers()
}

// prewarm adapts Listers to the prewarmer, which needs only the references.
func (p SecretEntityListers) prewarm() []func(context.Context, ids.GatewayID) ([]appsecretref.Use, error) {
	listers := p.Listers()
	out := make([]func(context.Context, ids.GatewayID) ([]appsecretref.Use, error), 0, len(listers))
	for _, list := range listers {
		out = append(out, func(ctx context.Context, gw ids.GatewayID) ([]appsecretref.Use, error) {
			entities, err := list(ctx, gw)
			if err != nil {
				return nil, err
			}
			var uses []appsecretref.Use
			for _, e := range entities {
				uses = append(uses, e.Uses...)
			}
			return uses, nil
		})
	}
	return out
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

// secretValuesParams is the plane's materializer, for readers outside the
// gateway's runtime data.
type secretValuesParams struct {
	dig.In
	Materializer appsecretref.Materializer `optional:"true"`
}

func (p secretValuesParams) credentialFinderOptions() []appauth.CredentialFinderOption {
	if p.Materializer == nil {
		return nil
	}
	return []appauth.CredentialFinderOption{appauth.WithSecretValues(p.Materializer)}
}

func (p secretRefsParams) authOptions() []appauth.SaveOption {
	if v := p.entity(); v != nil {
		return []appauth.SaveOption{appauth.WithSecretRefValidator(v)}
	}
	return nil
}

// OnInvalidate adds fn to what runs when a secret a gateway used changes, for
// caches built from resolved values outside the gateway's runtime data.
func (s *SecretStores) OnInvalidate(fn func(ids.GatewayID)) {
	if s == nil {
		return
	}
	s.invalidateMu.Lock()
	defer s.invalidateMu.Unlock()
	s.invalidators = append(s.invalidators, fn)
}

func (s *SecretStores) invalidate(gatewayID ids.GatewayID) {
	s.invalidateMu.Lock()
	fns := make([]func(ids.GatewayID), len(s.invalidators))
	copy(fns, s.invalidators)
	s.invalidateMu.Unlock()
	for _, fn := range fns {
		fn(gatewayID)
	}
}

func (p secretRefsParams) gatewayOptions() []appgateway.SaveOption {
	if v := p.entity(); v != nil {
		return []appgateway.SaveOption{appgateway.WithSecretRefValidator(v)}
	}
	return nil
}
