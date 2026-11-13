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

package secretref

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

const (
	prewarmPageSize       = 200
	prewarmConcurrency    = 8
	prewarmMinBackoff     = 2 * time.Second
	prewarmMaxBackoff     = 30 * time.Second
	prewarmGatewayTimeout = 10 * time.Second
)

// ErrPrewarmPending is what the readiness gate reports until the first
// prewarm pass leaves no reference failing for a transient reason.
var ErrPrewarmPending = errors.New("secret stores: references not prewarmed yet")

// GatewayLister pages through the gateways a plane serves.
type GatewayLister interface {
	List(ctx context.Context, filter gateway.ListFilter) ([]*gateway.Gateway, int, error)
}

// RegistryLister pages through a gateway's registries.
type RegistryLister interface {
	List(ctx context.Context, filter registry.ListFilter) ([]*registry.Registry, int, error)
}

// PrewarmConfig configures NewPrewarmer.
type PrewarmConfig struct {
	Catalog     secretstore.Catalog
	Resolver    Resolver
	Eligibility secretstore.Eligibility
	Gateways    GatewayLister
	Registries  RegistryLister
	// Loaded reports whether the plane has its configuration yet. A data
	// plane receives it asynchronously from config-sync, so a pass that ran
	// before is not a reason to report ready. Nil means always loaded, as on
	// a plane that reads Postgres.
	Loaded func() bool
	Logger *slog.Logger
}

// Prewarmer resolves, in the background, every reference of the eligible
// gateways a plane serves, so the first request does not wait for a store.
// A pass runs on Trigger: after a snapshot apply, a store-file reload or the
// first load. A pass that leaves a reference failing for a transient reason
// is retried with backoff.
type Prewarmer struct {
	cfg     PrewarmConfig
	trigger chan struct{}
	started atomic.Bool
	ready   atomic.Bool
	// minBackoff and maxBackoff space the retries of a pass that left a
	// reference failing for a transient reason.
	minBackoff, maxBackoff time.Duration
}

// NewPrewarmer returns a Prewarmer; Run starts it.
func NewPrewarmer(cfg PrewarmConfig) *Prewarmer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Prewarmer{cfg: cfg, trigger: make(chan struct{}, 1), minBackoff: prewarmMinBackoff, maxBackoff: prewarmMaxBackoff}
}

// Trigger asks for a pass; triggers that arrive during a pass coalesce into
// one more pass. The first trigger also arms the readiness gate.
func (p *Prewarmer) Trigger() {
	p.started.Store(true)
	select {
	case p.trigger <- struct{}{}:
	default:
	}
}

// Ready reports whether a pass that started with the plane's configuration
// loaded has completed with no reference failing for a transient reason. It
// stays true afterwards: a store blip once the plane serves must not take it
// out of rotation.
func (p *Prewarmer) Ready() bool { return p.ready.Load() }

// ReadinessCheck is the SECRET_STORES_READINESS_GATE check. A plane that
// never triggers the prewarmer, such as the admin, is not held back by it.
func (p *Prewarmer) ReadinessCheck(context.Context) error {
	if !p.started.Load() || p.Ready() {
		return nil
	}
	return ErrPrewarmPending
}

// Run serves triggers until ctx is done.
func (p *Prewarmer) Run(ctx context.Context) {
	backoff := p.minBackoff
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.trigger:
		case <-retry:
		}
		retry = nil
		loaded := p.cfg.Loaded == nil || p.cfg.Loaded()
		pending, err := p.pass(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil && pending == 0 && loaded {
			p.ready.Store(true)
			backoff = p.minBackoff
			continue
		}
		// A pass before the configuration arrived, or one that left
		// references failing for a transient reason, is retried.
		if err != nil {
			p.cfg.Logger.Warn("secret reference prewarm could not list the plane's configuration",
				slog.String("error", err.Error()))
		}
		retry = time.After(backoff)
		backoff = min(2*backoff, p.maxBackoff)
	}
}

// pass resolves every reference once and returns how many failed for a
// transient reason.
func (p *Prewarmer) pass(ctx context.Context) (int, error) {
	refs, err := p.collect(ctx)
	if err != nil {
		return 0, err
	}
	var pending atomic.Int64
	sem := make(chan struct{}, prewarmConcurrency)
	var wg sync.WaitGroup
	for _, ref := range refs {
		sem <- struct{}{}
		wg.Add(1)
		go func(ref domain.Ref) {
			defer func() { <-sem; wg.Done() }()
			if _, err := p.cfg.Resolver.Resolve(ctx, ref); err != nil && secretstore.ClassOf(err) == secretstore.ClassUnavailable {
				pending.Add(1)
			}
		}(ref)
	}
	wg.Wait()
	return int(pending.Load()), nil
}

// collect lists one reference per payload across the eligible gateways,
// keeping only those whose store admits the gateway and the path, exactly
// as the materializer would resolve them.
func (p *Prewarmer) collect(ctx context.Context) ([]domain.Ref, error) {
	seen := map[string]bool{}
	var refs []domain.Ref
	err := eachPage(func(page int) (int, int, error) {
		gws, total, err := p.cfg.Gateways.List(ctx, gateway.ListFilter{Page: page, Size: prewarmPageSize})
		if err != nil {
			return 0, 0, err
		}
		for _, gw := range gws {
			if !secretstore.Eligible(p.cfg.Eligibility, gw) {
				continue
			}
			found, err := p.gatewayRefs(ctx, gw)
			if err != nil {
				return 0, 0, err
			}
			for _, ref := range found {
				if key := ref.PayloadKey(); !seen[key] {
					seen[key] = true
					refs = append(refs, ref)
				}
			}
		}
		return len(gws), total, nil
	})
	return refs, err
}

func (p *Prewarmer) gatewayRefs(ctx context.Context, gw *gateway.Gateway) ([]domain.Ref, error) {
	ctx, cancel := context.WithTimeout(ctx, prewarmGatewayTimeout)
	defer cancel()
	var refs []domain.Ref
	err := eachPage(func(page int) (int, int, error) {
		regs, total, err := p.cfg.Registries.List(ctx, registry.ListFilter{GatewayID: gw.ID, Page: page, Size: prewarmPageSize})
		if err != nil {
			return 0, 0, err
		}
		for _, reg := range regs {
			uses, _ := RegistryReferences(reg)
			for _, u := range uses {
				ref, ok, err := domain.Parse(u.Raw)
				if !ok || err != nil {
					continue
				}
				store, _, found := p.cfg.Catalog.Get(ref.Store)
				if !found || store.Allows(gw.ID, ref.Path) != nil {
					continue
				}
				refs = append(refs, ref)
			}
		}
		return len(regs), total, nil
	})
	return refs, err
}

// eachPage calls list for pages 1, 2, … until it has seen total items or a
// page comes back empty.
func eachPage(list func(page int) (n, total int, err error)) error {
	seen := 0
	for page := 1; ; page++ {
		n, total, err := list(page)
		if err != nil {
			return err
		}
		seen += n
		if n == 0 || seen >= total {
			return nil
		}
	}
}
