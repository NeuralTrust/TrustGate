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
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/errgroup"

	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

const (
	unresolvedMetric      = "trustgate.secretstore.unresolved_references"
	materializeConcurrent = 8
	eligibilityTimeout    = 5 * time.Second
)

//go:generate mockery --name=Materializer --dir=. --output=./mocks --filename=secretref_materializer_mock.go --case=underscore --with-expecter

// Materializer turns the references held by a gateway's registries into
// values for its runtime data.
type Materializer interface {
	// Registries returns byID with every registry that holds a reference
	// replaced by a copy carrying the resolved values. A reference that
	// cannot be resolved is left empty and its copy is marked
	// CredentialUnavailable; it is never kept as the reference string. When
	// no registry holds a reference, byID itself is returned untouched. The
	// input registries are never modified.
	Registries(ctx context.Context, gatewayID ids.GatewayID, byID map[ids.RegistryID]*registry.Registry) map[ids.RegistryID]*registry.Registry
	// StoresChanged invalidates every gateway whose runtime data referenced
	// one of the named stores, after the store file added, changed or
	// removed them.
	StoresChanged(names []string)
}

// GatewayFinder reads a gateway's entitlements for the eligibility check.
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gateway.Gateway, error)
}

// MaterializerConfig configures NewMaterializer.
type MaterializerConfig struct {
	// Enabled is SECRET_STORES_ENABLED. Disabled, every reference stays
	// unresolved.
	Enabled bool
	// Eligibility is SECRET_STORES_GATEWAYS.
	Eligibility secretstore.Eligibility
	// Catalog and Resolver are nil on a plane without a store file, where
	// every reference stays unresolved.
	Catalog  secretstore.Catalog
	Resolver Resolver
	Gateways GatewayFinder
	// Invalidate drops a gateway's runtime data, so it is materialized again
	// after a value it used changed.
	Invalidate func(gatewayID ids.GatewayID)
	Logger     *slog.Logger
	Meter      metric.Meter
}

type materializer struct {
	cfg        MaterializerConfig
	unresolved metric.Int64Counter

	mu sync.Mutex
	// byPayload maps a payload key to the gateways whose runtime data used
	// it; byGateway is the reverse, so each materialization replaces its
	// gateway's entries instead of piling them up.
	byPayload map[string]map[ids.GatewayID]struct{}
	byGateway map[ids.GatewayID][]string
}

// NewMaterializer returns a Materializer. With a Resolver, it subscribes to
// its changes and invalidates the gateways that used a changed payload.
func NewMaterializer(cfg MaterializerConfig) Materializer {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	meter := cfg.Meter
	if meter == nil {
		meter = otel.Meter(meterName)
	}
	m := &materializer{
		cfg:       cfg,
		byPayload: map[string]map[ids.GatewayID]struct{}{},
		byGateway: map[ids.GatewayID][]string{},
	}
	counter, err := meter.Int64Counter(unresolvedMetric, metric.WithUnit("{reference}"),
		metric.WithDescription("references left empty while building a gateway's runtime data, by error class"))
	if err != nil {
		cfg.Logger.Warn("failed to create secret store metric", slog.String("metric", unresolvedMetric), slog.String("error", err.Error()))
	}
	m.unresolved = counter
	if cfg.Resolver != nil {
		cfg.Resolver.OnChange(m.onChange)
	}
	return m
}

type pending struct {
	registryID ids.RegistryID
	path       []string
	ref        domain.Ref
	parsed     bool
	value      string
	err        error
}

// Registries implements Materializer.
func (m *materializer) Registries(ctx context.Context, gatewayID ids.GatewayID, byID map[ids.RegistryID]*registry.Registry) map[ids.RegistryID]*registry.Registry {
	var refs []*pending
	for id, r := range byID {
		if !registryHasRef(r) {
			continue
		}
		for _, s := range registrySlots(r) {
			p := &pending{registryID: id, path: s.path}
			ref, _, err := domain.Parse(s.value)
			if err != nil {
				p.err = fmt.Errorf("%w: %v", secretstore.ErrInvalidPayload, err)
			} else {
				p.ref, p.parsed = ref, true
			}
			refs = append(refs, p)
		}
	}
	if len(refs) == 0 {
		m.index(gatewayID, nil)
		return byID
	}

	// The gateway is indexed before anything is read: a value that changes
	// while this load resolves must invalidate it, so the load is not cached
	// with the old value.
	var used []string
	for _, p := range refs {
		if p.parsed {
			used = append(used, p.ref.PayloadKey())
		}
	}
	m.index(gatewayID, used)

	m.resolveAll(ctx, gatewayID, refs)

	out := make(map[ids.RegistryID]*registry.Registry, len(byID))
	for id, r := range byID {
		out[id] = r
	}
	copies := map[ids.RegistryID]*registry.Registry{}
	for _, p := range refs {
		c, ok := copies[p.registryID]
		if !ok {
			c = copyRegistry(byID[p.registryID])
			copies[p.registryID] = c
			out[p.registryID] = c
		}
		if p.err != nil {
			c.MarkCredentialUnavailable()
			setSlot(c, p.path, "")
			m.reportUnresolved(ctx, gatewayID, p)
			continue
		}
		setSlot(c, p.path, p.value)
	}
	return out
}

// resolveAll checks and resolves every reference, reading distinct payloads
// concurrently so a gateway with many references waits about one fetch. The
// result is cached with the gateway's data, which is built once for every
// concurrent request, so it must not depend on the first caller staying:
// reads run detached from its cancellation, bounded by the fetch timeout.
func (m *materializer) resolveAll(ctx context.Context, gatewayID ids.GatewayID, refs []*pending) {
	ctx = context.WithoutCancel(ctx)
	eligible, eligErr := false, error(nil)
	if m.cfg.Enabled && m.cfg.Catalog != nil && m.cfg.Resolver != nil {
		eligible, eligErr = m.eligible(ctx, gatewayID)
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(materializeConcurrent)
	for _, p := range refs {
		if p.err != nil {
			continue
		}
		if err := m.check(gatewayID, p.ref, eligible, eligErr); err != nil {
			p.err = err
			continue
		}
		g.Go(func() error {
			p.value, p.err = m.cfg.Resolver.Resolve(gctx, p.ref)
			return nil
		})
	}
	_ = g.Wait() // the goroutines record their outcome on p and never fail the group
}

func (m *materializer) check(gatewayID ids.GatewayID, ref domain.Ref, eligible bool, eligErr error) error {
	if !m.cfg.Enabled || m.cfg.Catalog == nil || m.cfg.Resolver == nil {
		return fmt.Errorf("secret references are not enabled on this plane: %w", secretstore.ErrStoreMissing)
	}
	if eligErr != nil {
		return fmt.Errorf("the gateway's eligibility could not be read: %w", secretstore.ErrNotAllowed)
	}
	if !eligible {
		return fmt.Errorf("the gateway may not use secret references: %w", secretstore.ErrNotAllowed)
	}
	store, _, ok := m.cfg.Catalog.Get(ref.Store)
	if !ok {
		return fmt.Errorf("secret store %q: %w", ref.Store, secretstore.ErrStoreMissing)
	}
	return store.Allows(gatewayID, ref.Path)
}

// eligible reads the gateway only when needed: under EligibilityAll every
// gateway qualifies. A gateway that cannot be read is not eligible.
func (m *materializer) eligible(ctx context.Context, gatewayID ids.GatewayID) (bool, error) {
	if m.cfg.Eligibility == secretstore.EligibilityAll {
		return true, nil
	}
	if m.cfg.Gateways == nil {
		return false, errors.New("no gateway reader")
	}
	ctx, cancel := context.WithTimeout(ctx, eligibilityTimeout)
	defer cancel()
	gw, err := m.cfg.Gateways.FindByID(ctx, gatewayID)
	if err != nil {
		return false, err
	}
	return secretstore.Eligible(m.cfg.Eligibility, gw), nil
}

func (m *materializer) reportUnresolved(ctx context.Context, gatewayID ids.GatewayID, p *pending) {
	class := secretstore.ClassOf(p.err)
	attrs := []any{
		slog.String("gateway_id", gatewayID.String()),
		slog.String("registry_id", p.registryID.String()),
		slog.String("location", strings.Join(p.path, ".")),
		slog.String("error_class", string(class)),
	}
	if p.parsed {
		attrs = append(attrs, slog.String("store", p.ref.Store), slog.String("path", p.ref.Path))
	}
	m.cfg.Logger.Warn("secret reference unresolved; the registry fails with secret_unavailable", attrs...)
	if m.unresolved != nil {
		m.unresolved.Add(ctx, 1, metric.WithAttributes(attribute.String("error_class", string(class))))
	}
}

// index records the payloads gatewayID's runtime data used, replacing what
// it used before.
func (m *materializer) index(gatewayID ids.GatewayID, payloads []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, key := range m.byGateway[gatewayID] {
		if set := m.byPayload[key]; set != nil {
			delete(set, gatewayID)
			if len(set) == 0 {
				delete(m.byPayload, key)
			}
		}
	}
	if len(payloads) == 0 {
		delete(m.byGateway, gatewayID)
		return
	}
	m.byGateway[gatewayID] = payloads
	for _, key := range payloads {
		set := m.byPayload[key]
		if set == nil {
			set = map[ids.GatewayID]struct{}{}
			m.byPayload[key] = set
		}
		set[gatewayID] = struct{}{}
	}
}

// StoresChanged implements Materializer.
func (m *materializer) StoresChanged(names []string) {
	if m.cfg.Invalidate == nil || len(names) == 0 {
		return
	}
	m.mu.Lock()
	affected := map[ids.GatewayID]struct{}{}
	for key, gateways := range m.byPayload {
		for _, name := range names {
			if strings.HasPrefix(key, name+"\x00") {
				for gw := range gateways {
					affected[gw] = struct{}{}
				}
			}
		}
	}
	m.mu.Unlock()
	for gw := range affected {
		m.cfg.Invalidate(gw)
	}
}

func (m *materializer) onChange(payloads []domain.Ref) {
	if m.cfg.Invalidate == nil {
		return
	}
	m.mu.Lock()
	affected := map[ids.GatewayID]struct{}{}
	for _, p := range payloads {
		for gw := range m.byPayload[p.PayloadKey()] {
			affected[gw] = struct{}{}
		}
	}
	m.mu.Unlock()
	for gw := range affected {
		m.cfg.Invalidate(gw)
	}
}
