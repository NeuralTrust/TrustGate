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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"log/slog"
	"sort"
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
	// GatewayRegistries is Registries for the complete set of a gateway's
	// registries, as its runtime data is built: it also records which
	// payloads the gateway uses, replacing what it used before, so a change
	// to any of them invalidates the gateway. Only the builder of a
	// gateway's runtime data calls it.
	GatewayRegistries(ctx context.Context, gatewayID ids.GatewayID, byID map[ids.RegistryID]*registry.Registry) map[ids.RegistryID]*registry.Registry
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
	// Refresh re-reads the references of reg, a copy Registries built, after
	// an upstream rejected its credential. It returns a new copy and true
	// when a value changed, so the call can be retried once with it.
	Refresh(ctx context.Context, reg *registry.Registry) (*registry.Registry, bool)
	// Health reports the last outcome of every reference resolved for a
	// gateway's runtime data, failing ones first.
	Health() secretstore.RefHealth
	// Values resolves the reference-shaped values of uses, declared
	// locations of other entities of gatewayID, with the same checks as
	// registries: eligibility, the store's gateway allowlist and allowed
	// paths. A value that cannot be resolved comes back empty with its
	// error, never as the reference. With a source, the payloads are
	// recorded as what that part of the gateway's runtime data uses,
	// replacing what it used before, so a change invalidates the gateway;
	// with an empty source nothing is recorded.
	Values(ctx context.Context, gatewayID ids.GatewayID, source string, uses []Use) []Resolved
}

// Resolved is the outcome of one Use: the value, or the error that left it
// empty.
type Resolved struct {
	Value string
	Err   error
}

// Sources of a gateway's runtime data, for Values.
const (
	SourceRegistries = "registries"
	SourceConsumers  = "consumers"
	SourcePolicies   = "policies"
	SourceAuths      = "auths"
	// SourceAuthCredentials is the identity providers the credential finder
	// caches apart from the gateway's runtime data.
	SourceAuthCredentials = "auth_credentials"
	SourceGateway         = "gateway"
)

// GatewayFinder reads a gateway's entitlements for the eligibility check.
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gateway.Gateway, error)
}

// MaterializerConfig configures NewMaterializer.
type MaterializerConfig struct {
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
	// digestKey keys the fingerprints of resolved values. It is random per
	// process, so a fingerprint cannot be checked against a guessed value
	// outside this process.
	digestKey []byte

	mu sync.Mutex
	// byPayload maps a payload key to the gateways whose runtime data used
	// it; byGateway is the reverse, per source of the gateway's data, so each
	// materialization replaces its own entries instead of piling them up.
	byPayload map[string]map[ids.GatewayID]struct{}
	byGateway map[ids.GatewayID]map[string][]string
	// outcomes holds, per gateway and source, the outcome of each reference
	// the last materialization of that source resolved; each one replaces
	// what its source held, so removed references leave it.
	outcomes map[ids.GatewayID]map[string][]secretstore.RefOutcome
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
		digestKey: []byte(rand.Text()),
		byPayload: map[string]map[ids.GatewayID]struct{}{},
		byGateway: map[ids.GatewayID]map[string][]string{},
		outcomes:  map[ids.GatewayID]map[string][]secretstore.RefOutcome{},
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
	// entity and id name the entity that holds the reference.
	entity string
	id     string
	path   []string
	// hosts are where the value is sent; self marks a value that names its
	// own host. A store with allowed destinations checks them.
	hosts  []string
	self   bool
	ref    domain.Ref
	parsed bool
	value  string
	err    error
}

// GatewayRegistries implements Materializer.
func (m *materializer) GatewayRegistries(ctx context.Context, gatewayID ids.GatewayID, byID map[ids.RegistryID]*registry.Registry) map[ids.RegistryID]*registry.Registry {
	return m.materialize(ctx, gatewayID, byID, true)
}

// Registries implements Materializer. It leaves the gateway's index alone:
// its callers read a few registries, not the gateway's runtime data.
func (m *materializer) Registries(ctx context.Context, gatewayID ids.GatewayID, byID map[ids.RegistryID]*registry.Registry) map[ids.RegistryID]*registry.Registry {
	return m.materialize(ctx, gatewayID, byID, false)
}

func (m *materializer) materialize(ctx context.Context, gatewayID ids.GatewayID, byID map[ids.RegistryID]*registry.Registry, index bool) map[ids.RegistryID]*registry.Registry {
	var refs []*pending
	for id, r := range byID {
		if !registryHasRef(r) {
			continue
		}
		for _, s := range registrySlots(r) {
			p := &pending{registryID: id, entity: string(domain.EntityRegistry), id: id.String(), path: s.path, hosts: s.hosts}
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
		if index {
			m.index(gatewayID, SourceRegistries, nil)
			m.record(gatewayID, SourceRegistries, nil)
		}
		return byID
	}

	// The gateway is indexed before anything is read: a value that changes
	// while this load resolves must invalidate it, so the load is not cached
	// with the old value.
	if index {
		var used []string
		for _, p := range refs {
			if p.parsed {
				used = append(used, p.ref.PayloadKey())
			}
		}
		m.index(gatewayID, SourceRegistries, used)
	}

	if eligErr := m.resolveAll(ctx, gatewayID, refs); eligErr != nil && index && m.cfg.Invalidate != nil {
		// The eligibility read failed, not the gateway: dropping its data
		// moves the cache generation on, so this load is not kept and the
		// next request reads the gateway again.
		m.cfg.Invalidate(gatewayID)
	}

	if index {
		m.record(gatewayID, SourceRegistries, refs)
	}
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
	for id, c := range copies {
		c.BindSecrets(byID[id], m.digest(id, refs))
	}
	return out
}

// digest fingerprints the values resolved for registry id with a keyed hash.
func (m *materializer) digest(id ids.RegistryID, refs []*pending) string {
	var parts []string
	for _, p := range refs {
		if p.registryID == id && p.err == nil {
			parts = append(parts, strings.Join(p.path, ".")+"\x00"+p.value)
		}
	}
	sort.Strings(parts)
	mac := hmac.New(sha256.New, m.digestKey)
	for _, part := range parts {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil)[:12])
}

// Refresh implements Materializer.
func (m *materializer) Refresh(ctx context.Context, reg *registry.Registry) (*registry.Registry, bool) {
	src := reg.SecretSource()
	if src == nil || m.cfg.Resolver == nil {
		return nil, false
	}
	var refs []domain.Ref
	for _, s := range registrySlots(src) {
		if ref, ok, err := domain.Parse(s.value); ok && err == nil {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return nil, false
	}
	changed, _ := m.cfg.Resolver.ForceRefresh(ctx, refs)
	if !changed {
		return nil, false
	}
	fresh := m.Registries(ctx, src.GatewayID, map[ids.RegistryID]*registry.Registry{src.ID: src})[src.ID]
	return fresh, true
}

// resolveAll checks and resolves every reference and returns the error of
// reading the gateway's eligibility, if any. Distinct payloads are read
// concurrently, so a gateway with many references waits about one fetch. The
// result is cached with the gateway's data, which is built once for every
// concurrent request, so it must not depend on the first caller staying:
// reads run detached from its cancellation, bounded by the fetch timeout.
func (m *materializer) resolveAll(ctx context.Context, gatewayID ids.GatewayID, refs []*pending) error {
	ctx = context.WithoutCancel(ctx)
	eligible, eligErr := false, error(nil)
	if m.cfg.Catalog != nil && m.cfg.Resolver != nil {
		eligible, eligErr = m.eligible(ctx, gatewayID)
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(materializeConcurrent)
	for _, p := range refs {
		if p.err != nil {
			continue
		}
		if err := m.check(gatewayID, p, eligible, eligErr); err != nil {
			p.err = err
			continue
		}
		g.Go(func() error {
			p.value, p.err = m.cfg.Resolver.Resolve(gctx, p.ref)
			return nil
		})
	}
	_ = g.Wait() // the goroutines record their outcome on p and never fail the group
	return eligErr
}

func (m *materializer) check(gatewayID ids.GatewayID, p *pending, eligible bool, eligErr error) error {
	ref := p.ref
	if m.cfg.Catalog == nil || m.cfg.Resolver == nil {
		return fmt.Errorf("this plane loads no secret store: %w", secretstore.ErrStoreMissing)
	}
	if eligErr != nil {
		return fmt.Errorf("the gateway's eligibility could not be read: %w", secretstore.ErrUnavailable)
	}
	if !eligible {
		return fmt.Errorf("the gateway may not use secret references: %w", secretstore.ErrNotAllowed)
	}
	store, _, ok := m.cfg.Catalog.Get(ref.Store)
	if !ok {
		return fmt.Errorf("secret store %q: %w", ref.Store, secretstore.ErrStoreMissing)
	}
	if err := store.Allows(gatewayID, ref.Path); err != nil {
		return err
	}
	if p.self {
		return nil
	}
	return store.AllowsDestinations(p.hosts)
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
		slog.String("location", strings.Join(p.path, ".")),
		slog.String("error_class", string(class)),
	}
	if p.registryID != (ids.RegistryID{}) {
		attrs = append(attrs, slog.String("registry_id", p.registryID.String()))
	}
	if p.parsed {
		attrs = append(attrs, slog.String("store", p.ref.Store), slog.String("path", p.ref.Path))
	}
	m.cfg.Logger.Warn("secret reference unresolved; its credential is left empty", attrs...)
	if m.unresolved != nil {
		m.unresolved.Add(ctx, 1, metric.WithAttributes(attribute.String("error_class", string(class))))
	}
}

// index records the payloads source of gatewayID's runtime data used,
// replacing what that source used before; the other sources are kept.
func (m *materializer) index(gatewayID ids.GatewayID, source string, payloads []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	before := m.usedLocked(gatewayID)
	sources := m.byGateway[gatewayID]
	if len(payloads) == 0 {
		delete(sources, source)
	} else {
		if sources == nil {
			sources = map[string][]string{}
			m.byGateway[gatewayID] = sources
		}
		sources[source] = payloads
	}
	if len(sources) == 0 {
		delete(m.byGateway, gatewayID)
	}
	after := m.usedLocked(gatewayID)
	for key := range before {
		if _, ok := after[key]; ok {
			continue
		}
		if set := m.byPayload[key]; set != nil {
			delete(set, gatewayID)
			if len(set) == 0 {
				delete(m.byPayload, key)
			}
		}
	}
	for key := range after {
		set := m.byPayload[key]
		if set == nil {
			set = map[ids.GatewayID]struct{}{}
			m.byPayload[key] = set
		}
		set[gatewayID] = struct{}{}
	}
}

// unindex removes gatewayID from the index, every source of it.
func (m *materializer) unindex(gatewayID ids.GatewayID) {
	m.mu.Lock()
	sources := make([]string, 0, len(m.byGateway[gatewayID]))
	for source := range m.byGateway[gatewayID] {
		sources = append(sources, source)
	}
	m.mu.Unlock()
	for _, source := range sources {
		m.index(gatewayID, source, nil)
	}
	m.mu.Lock()
	delete(m.outcomes, gatewayID)
	m.mu.Unlock()
}

// record replaces what source of gatewayID's runtime data last resolved.
func (m *materializer) record(gatewayID ids.GatewayID, source string, refs []*pending) {
	outcomes := make([]secretstore.RefOutcome, 0, len(refs))
	for _, p := range refs {
		o := secretstore.RefOutcome{
			GatewayID: gatewayID, Entity: p.entity, ID: p.id, Field: strings.Join(p.path, "."),
			Class: secretstore.ClassOf(p.err),
		}
		if p.parsed {
			o.Store, o.Path = p.ref.Store, p.ref.Path
		}
		outcomes = append(outcomes, o)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sources := m.outcomes[gatewayID]
	if len(outcomes) == 0 {
		delete(sources, source)
		if len(sources) == 0 {
			delete(m.outcomes, gatewayID)
		}
		return
	}
	if sources == nil {
		sources = map[string][]secretstore.RefOutcome{}
		m.outcomes[gatewayID] = sources
	}
	sources[source] = outcomes
}

// Health implements Materializer. A reference two sources resolved, such as
// an auth read for the runtime data and for the credential finder, counts
// once, failing if either failed.
func (m *materializer) Health() secretstore.RefHealth {
	type key struct {
		gw                             ids.GatewayID
		entity, id, field, store, path string
	}
	m.mu.Lock()
	merged := map[key]secretstore.RefOutcome{}
	for _, sources := range m.outcomes {
		for _, outcomes := range sources {
			for _, o := range outcomes {
				k := key{o.GatewayID, o.Entity, o.ID, o.Field, o.Store, o.Path}
				if prev, ok := merged[k]; ok && prev.Class != "" {
					continue
				}
				merged[k] = o
			}
		}
	}
	m.mu.Unlock()
	h := secretstore.RefHealth{Total: len(merged), Outcomes: make([]secretstore.RefOutcome, 0, len(merged))}
	for _, o := range merged {
		if o.Class != "" {
			h.Unresolved++
		}
		h.Outcomes = append(h.Outcomes, o)
	}
	sort.Slice(h.Outcomes, func(i, j int) bool {
		a, b := h.Outcomes[i], h.Outcomes[j]
		if (a.Class != "") != (b.Class != "") {
			return a.Class != ""
		}
		if a.GatewayID != b.GatewayID {
			return a.GatewayID.String() < b.GatewayID.String()
		}
		if a.Entity != b.Entity {
			return a.Entity < b.Entity
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Field < b.Field
	})
	if len(h.Outcomes) > secretstore.MaxRefOutcomes {
		h.Outcomes = h.Outcomes[:secretstore.MaxRefOutcomes]
	}
	return h
}

func (m *materializer) usedLocked(gatewayID ids.GatewayID) map[string]struct{} {
	used := map[string]struct{}{}
	for _, payloads := range m.byGateway[gatewayID] {
		for _, key := range payloads {
			used[key] = struct{}{}
		}
	}
	return used
}

// Values implements Materializer.
func (m *materializer) Values(ctx context.Context, gatewayID ids.GatewayID, source string, uses []Use) []Resolved {
	out := make([]Resolved, len(uses))
	if len(uses) == 0 {
		if source != "" {
			m.index(gatewayID, source, nil)
			m.record(gatewayID, source, nil)
		}
		return out
	}
	refs := make([]*pending, len(uses))
	var used []string
	for i, u := range uses {
		p := &pending{path: u.Path, hosts: u.Hosts, self: u.SelfAddressed, entity: string(u.Entity), id: u.ID}
		ref, _, err := domain.Parse(u.Raw)
		if err != nil {
			p.err = fmt.Errorf("%w: %v", secretstore.ErrInvalidPayload, err)
		} else {
			p.ref, p.parsed = ref, true
			used = append(used, ref.PayloadKey())
		}
		refs[i] = p
	}
	if source != "" {
		m.index(gatewayID, source, used)
	}
	if eligErr := m.resolveAll(ctx, gatewayID, refs); eligErr != nil && source != "" && m.cfg.Invalidate != nil {
		m.cfg.Invalidate(gatewayID)
	}
	if source != "" {
		m.record(gatewayID, source, refs)
	}
	for i, p := range refs {
		out[i] = Resolved{Value: p.value, Err: p.err}
		if p.err != nil {
			out[i].Value = ""
			m.reportUnresolved(ctx, gatewayID, p)
		}
	}
	return out
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
	m.invalidate(affected)
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
	m.invalidate(affected)
}

// invalidate drops the runtime data of the affected gateways. A gateway that
// no longer exists leaves the index instead, so deleted gateways do not
// accumulate in it.
func (m *materializer) invalidate(affected map[ids.GatewayID]struct{}) {
	for gw := range affected {
		if m.deleted(gw) {
			m.unindex(gw)
			continue
		}
		m.cfg.Invalidate(gw)
	}
}

func (m *materializer) deleted(gatewayID ids.GatewayID) bool {
	if m.cfg.Gateways == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), eligibilityTimeout)
	defer cancel()
	_, err := m.cfg.Gateways.FindByID(ctx, gatewayID)
	return errors.Is(err, commonerrors.ErrNotFound)
}
