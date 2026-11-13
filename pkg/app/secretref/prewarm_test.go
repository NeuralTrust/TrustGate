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
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

type scriptedResolver struct {
	mu       sync.Mutex
	errs     []error
	resolved []string
}

func (r *scriptedResolver) Resolve(_ context.Context, ref domain.Ref) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolved = append(r.resolved, ref.Store+"/"+ref.Path)
	if len(r.errs) == 0 {
		return "value", nil
	}
	err := r.errs[0]
	r.errs = r.errs[1:]
	return "", err
}

func (r *scriptedResolver) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.resolved...)
	sort.Strings(out)
	return out
}

func (*scriptedResolver) ForceRefresh(context.Context, []domain.Ref) (bool, error) { return false, nil }
func (*scriptedResolver) OnChange(func([]domain.Ref))                              {}

type gatewayList []*gateway.Gateway

func (l gatewayList) List(context.Context, gateway.ListFilter) ([]*gateway.Gateway, int, error) {
	return l, len(l), nil
}

type swappableGateways struct {
	mu   sync.Mutex
	list GatewayLister
}

func (s *swappableGateways) set(l GatewayLister) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = l
}

func (s *swappableGateways) List(ctx context.Context, f gateway.ListFilter) ([]*gateway.Gateway, int, error) {
	s.mu.Lock()
	l := s.list
	s.mu.Unlock()
	return l.List(ctx, f)
}

type registryList map[ids.GatewayID][]*registry.Registry

func (l registryList) List(_ context.Context, f registry.ListFilter) ([]*registry.Registry, int, error) {
	return l[f.GatewayID], len(l[f.GatewayID]), nil
}

func refRegistry(gw ids.GatewayID, apiKey string) *registry.Registry {
	reg := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, Type: registry.TypeLLM}
	reg.LLMTarget = &registry.LLMTarget{Provider: "openai", Auth: registry.NewAPIKeyAuth(apiKey)}
	return reg
}

func prewarmFixture(resolver Resolver) (*Prewarmer, ids.GatewayID) {
	hybrid := &gateway.Gateway{ID: ids.New[ids.GatewayKind](), Entitlements: gateway.Entitlements{DataPlane: "hybrid"}}
	saas := &gateway.Gateway{ID: ids.New[ids.GatewayKind]()}
	other := ids.New[ids.GatewayKind]()
	catalog := &fakeCatalog{
		stores: map[string]*secretstore.Store{
			"vault":  {Name: "vault", AllowedPaths: []string{"llm/"}},
			"locked": {Name: "locked", AllowedPaths: []string{secretstore.AllPaths}, Gateways: []ids.GatewayID{other}},
		},
		backend: map[string]secretstore.Backend{},
	}
	p := NewPrewarmer(PrewarmConfig{
		Catalog:     catalog,
		Resolver:    resolver,
		Eligibility: secretstore.EligibilityHybrid,
		Gateways:    gatewayList{hybrid, saas},
		Registries: registryList{
			hybrid.ID: {
				refRegistry(hybrid.ID, "secret://vault/llm/openai#a"),
				refRegistry(hybrid.ID, "secret://vault/llm/openai#b"),
				refRegistry(hybrid.ID, "secret://vault/prod/db"),
				refRegistry(hybrid.ID, "secret://locked/x"),
				refRegistry(hybrid.ID, "secret://missing/x"),
				refRegistry(hybrid.ID, "sk-literal"),
			},
			saas.ID: {refRegistry(saas.ID, "secret://vault/llm/saas")},
		},
	})
	p.minBackoff, p.maxBackoff = 10*time.Millisecond, 20*time.Millisecond
	return p, hybrid.ID
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPrewarmResolvesWhatTheMaterializerWould(t *testing.T) {
	resolver := &scriptedResolver{}
	p, _ := prewarmFixture(resolver)
	pending, err := p.pass(context.Background())
	if err != nil || pending != 0 {
		t.Fatalf("pass = %d, %v", pending, err)
	}
	got := resolver.calls()
	if len(got) != 1 || got[0] != "vault/llm/openai" {
		t.Fatalf("resolved %v; want one fetch per payload, only eligible gateways, allowed stores and paths", got)
	}
}

func TestPrewarmReadinessGate(t *testing.T) {
	resolver := &scriptedResolver{errs: []error{
		secretstore.ErrUnavailable,
		secretstore.ErrUnavailable,
	}}
	p, _ := prewarmFixture(resolver)
	if err := p.ReadinessCheck(context.Background()); err != nil {
		t.Fatalf("before the first trigger the gate must not hold the plane back: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Trigger()
	if err := p.ReadinessCheck(context.Background()); !errors.Is(err, ErrPrewarmPending) {
		t.Fatalf("after the trigger and before a clean pass: %v", err)
	}
	go p.Run(ctx)
	waitFor(t, p.Ready)
	if n := len(resolver.calls()); n != 3 {
		t.Fatalf("resolves = %d, want two transient failures retried, then success", n)
	}

	resolver.mu.Lock()
	resolver.errs = []error{secretstore.ErrUnavailable}
	resolver.mu.Unlock()
	p.Trigger()
	waitFor(t, func() bool { return len(resolver.calls()) >= 4 })
	if err := p.ReadinessCheck(context.Background()); err != nil {
		t.Fatalf("a store blip after the plane became ready must not take it out of rotation: %v", err)
	}
}

func TestPrewarmTreatsDefinitiveFailuresAsDone(t *testing.T) {
	resolver := &scriptedResolver{errs: []error{secretstore.ErrNotFound}}
	p, _ := prewarmFixture(resolver)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Trigger()
	go p.Run(ctx)
	waitFor(t, p.Ready)
}

func TestPrewarmIsNotReadyUntilTheConfigurationArrives(t *testing.T) {
	resolver := &scriptedResolver{errs: []error{secretstore.ErrUnavailable, secretstore.ErrUnavailable}}
	p, _ := prewarmFixture(resolver)
	gateways := &swappableGateways{}
	gateways.set(gatewayList{})
	full := p.cfg.Gateways
	p.cfg.Gateways = gateways
	var loaded atomic.Bool
	p.cfg.Loaded = loaded.Load
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Trigger()
	go p.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	if p.Ready() {
		t.Fatal("a clean pass over an empty, not yet loaded configuration must not make the plane ready")
	}

	gateways.set(full)
	loaded.Store(true)
	p.Trigger()
	waitFor(t, p.Ready)
	if n := len(resolver.calls()); n != 3 {
		t.Fatalf("resolves = %d, want two transient failures retried, then success", n)
	}
}
