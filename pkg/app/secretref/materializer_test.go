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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
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

// markerResolver answers each reference with "resolved:<path>#<field>", so a
// test can tell which location received which value.
type markerResolver struct {
	mu        sync.Mutex
	calls     int
	err       error
	delay     time.Duration
	listeners []func([]domain.Ref)
}

func (r *markerResolver) Resolve(ctx context.Context, ref domain.Ref) (string, error) {
	r.mu.Lock()
	r.calls++
	err, delay := r.err, r.delay
	r.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if err != nil {
		return "", err
	}
	return "resolved:" + ref.Path + "#" + ref.Field, nil
}

func (r *markerResolver) ForceRefresh(context.Context, []domain.Ref) (bool, error) { return false, nil }

func (r *markerResolver) OnChange(fn func([]domain.Ref)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listeners = append(r.listeners, fn)
}

func (r *markerResolver) fire(p []domain.Ref) {
	r.mu.Lock()
	ls := append([]func([]domain.Ref){}, r.listeners...)
	r.mu.Unlock()
	for _, fn := range ls {
		fn(p)
	}
}

type gatewayFinder struct {
	gw    *gateway.Gateway
	err   error
	calls atomic.Int64
}

func (g *gatewayFinder) FindByID(context.Context, ids.GatewayID) (*gateway.Gateway, error) {
	g.calls.Add(1)
	return g.gw, g.err
}

func storeCatalog(gateways ...ids.GatewayID) *fakeCatalog {
	return &fakeCatalog{stores: map[string]*secretstore.Store{
		"vault": {Name: "vault", Type: secretstore.TypeHashiCorpVault, AllowedPaths: []string{"ai/"}, Gateways: gateways},
	}}
}

type invalidations struct {
	mu  sync.Mutex
	got []ids.GatewayID
}

func (i *invalidations) add(gw ids.GatewayID) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.got = append(i.got, gw)
}

func (i *invalidations) list() []ids.GatewayID {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]ids.GatewayID(nil), i.got...)
}

func newMat(t *testing.T, cfg MaterializerConfig) Materializer {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return NewMaterializer(cfg)
}

func refStr(path string) string { return "secret://vault/ai/" + path }

// everyLocation fills each declared location with a distinct reference.
func everyLocation() *registry.Registry {
	return &registry.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Name: "all",
		LLMTarget: &registry.LLMTarget{
			Provider: "openai",
			ProviderOptions: map[string]any{
				"base_url": "https://api.example",
				"headers":  map[string]any{"X-A": refStr("h1#v"), "X-Plain": "literal"},
			},
			Auth: &registry.TargetAuth{
				Type:              registry.AuthTypeAPIKey,
				APIKey:            &registry.APIKeyAuth{APIKey: refStr("k#a"), HeaderName: "X-K", HeaderValue: refStr("k#h"), ParamValue: refStr("k#p")},
				AWS:               &registry.AWSAuth{AccessKeyID: refStr("aws#id"), SecretAccessKey: refStr("aws#sk"), SessionToken: refStr("aws#st"), Region: "eu-west-1"},
				Azure:             &registry.AzureAuth{APIKey: refStr("az#k"), ClientSecret: refStr("az#cs"), Endpoint: "https://az"},
				OAuth:             &registry.TargetOAuthConfig{ClientSecret: refStr("o#cs"), RefreshToken: refStr("o#rt"), Password: refStr("o#pw"), TokenURL: "https://t"},
				GCPServiceAccount: ptr(refStr("gcp")),
			},
		},
		MCPTarget: &registry.MCPTarget{
			URL:     "https://mcp",
			Headers: map[string]string{"X-M": refStr("mh#v"), "X-Literal": "plain"},
			Auth:    &registry.MCPAuth{Mode: registry.MCPAuthModeStatic, Header: "Authorization", Value: refStr("mv#v"), ClientSecret: refStr("mcs#v")},
		},
	}
}

func ptr[T any](v T) *T { return &v }

func jsonLeaves(t *testing.T, r *registry.Registry) map[string]string {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	var walk func(any, []string)
	walk = func(n any, path []string) {
		switch v := n.(type) {
		case map[string]any:
			for k, c := range v {
				walk(c, append(append([]string(nil), path...), k))
			}
		case string:
			out[strings.Join(path, "\x1f")] = v
		}
	}
	walk(doc, nil)
	return out
}

func TestMaterializeEveryLocation(t *testing.T) {
	t.Parallel()
	in := everyLocation()
	before := jsonLeaves(t, in)
	m := newMat(t, MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}})
	out := m.Registries(context.Background(), ids.New[ids.GatewayKind](), map[ids.RegistryID]*registry.Registry{in.ID: in})
	got := out[in.ID]
	if got == in {
		t.Fatal("a registry with references must be replaced by a copy")
	}
	if got.CredentialUnavailable() {
		t.Fatal("every reference resolved")
	}
	if !reflect.DeepEqual(jsonLeaves(t, in), before) {
		t.Fatal("the input registry was modified")
	}
	after := jsonLeaves(t, got)
	resolved := 0
	for key, old := range before {
		path := strings.Split(key, "\x1f")
		now := after[key]
		if !domain.IsRef(old) {
			if now != old {
				t.Errorf("%v changed from %q to %q", path, old, now)
			}
			continue
		}
		if !domain.IsLocation(domain.EntityRegistry, path) {
			t.Errorf("fixture holds a reference outside a declared location: %v", path)
			continue
		}
		parsed, _, _ := domain.Parse(old)
		if want := "resolved:" + parsed.Path + "#" + parsed.Field; now != want {
			t.Errorf("%v = %q, want %q", path, now, want)
		}
		resolved++
	}
	if resolved != len(domain.Locations) {
		t.Fatalf("resolved %d locations, the fixture must cover all %d declared ones", resolved, len(domain.Locations))
	}
}

func TestFastPathReturnsTheInput(t *testing.T) {
	plain := everyLocation()
	plain.LLMTarget.Auth = registry.NewAPIKeyAuth("sk-live")
	plain.LLMTarget.ProviderOptions = map[string]any{"headers": map[string]string{"X": "y"}}
	plain.MCPTarget.Headers = map[string]string{"X": "y"}
	plain.MCPTarget.Auth.Value, plain.MCPTarget.Auth.ClientSecret = "v", ""
	byID := map[ids.RegistryID]*registry.Registry{plain.ID: plain}
	m := newMat(t, MaterializerConfig{})
	gw := ids.New[ids.GatewayKind]()
	if got := m.Registries(context.Background(), gw, byID); reflect.ValueOf(got).Pointer() != reflect.ValueOf(byID).Pointer() {
		t.Fatal("without references the input map must be returned as is")
	}
	allocs := testing.AllocsPerRun(100, func() { m.Registries(context.Background(), gw, byID) })
	if allocs != 0 {
		t.Fatalf("fast path allocates %v times", allocs)
	}
}

func TestUnresolvedIsEmptyAndMarked(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	other := ids.New[ids.GatewayKind]()
	hybrid := &gatewayFinder{gw: &gateway.Gateway{Entitlements: gateway.Entitlements{DataPlane: gateway.DataPlaneHybrid}}}
	hosted := &gatewayFinder{gw: &gateway.Gateway{}}
	tests := map[string]struct {
		cfg MaterializerConfig
		ref string
	}{
		"feature off":         {MaterializerConfig{Catalog: storeCatalog(), Resolver: &markerResolver{}, Eligibility: secretstore.EligibilityAll}, refStr("k")},
		"no store file":       {MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll}, refStr("k")},
		"hosted gateway":      {MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityHybrid, Gateways: hosted, Catalog: storeCatalog(), Resolver: &markerResolver{}}, refStr("k")},
		"gateway unreadable":  {MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityHybrid, Gateways: &gatewayFinder{err: errors.New("db")}, Catalog: storeCatalog(), Resolver: &markerResolver{}}, refStr("k")},
		"not in allowlist":    {MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(other), Resolver: &markerResolver{}}, refStr("k")},
		"path not allowed":    {MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}}, "secret://vault/payments/db"},
		"unknown store":       {MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}}, "secret://nope/ai/k"},
		"malformed reference": {MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}}, "secret://vault"},
		"store failure":       {MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityHybrid, Gateways: hybrid, Catalog: storeCatalog(), Resolver: &markerResolver{err: secretstore.ErrNotFound}}, refStr("k")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(tt.ref)}}
			out := newMat(t, tt.cfg).Registries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{in.ID: in})[in.ID]
			if !out.CredentialUnavailable() {
				t.Fatal("an unresolved reference must mark the copy")
			}
			if v := out.LLMTarget.Auth.APIKey.APIKey; v != "" {
				t.Fatalf("api_key = %q, want empty: a reference is never kept", v)
			}
			if in.CredentialUnavailable() || in.LLMTarget.Auth.APIKey.APIKey != tt.ref {
				t.Fatal("the input was modified")
			}
		})
	}
}

func TestHostedEligibilityReadsTheGatewayOnlyWithReferences(t *testing.T) {
	t.Parallel()
	finder := &gatewayFinder{gw: &gateway.Gateway{Entitlements: gateway.Entitlements{DataPlane: gateway.DataPlaneHybrid}}}
	m := newMat(t, MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityHybrid, Gateways: finder, Catalog: storeCatalog(), Resolver: &markerResolver{}})
	plain := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth("sk")}}
	m.Registries(context.Background(), ids.New[ids.GatewayKind](), map[ids.RegistryID]*registry.Registry{plain.ID: plain})
	if finder.calls.Load() != 0 {
		t.Fatal("a gateway without references must not be read")
	}
	withRef := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("k"))}}
	out := m.Registries(context.Background(), ids.New[ids.GatewayKind](), map[ids.RegistryID]*registry.Registry{withRef.ID: withRef})
	if out[withRef.ID].CredentialUnavailable() || out[withRef.ID].LLMTarget.Auth.APIKey.APIKey != "resolved:ai/k#" {
		t.Fatalf("hybrid gateway: %+v", out[withRef.ID].LLMTarget.Auth.APIKey)
	}
}

func TestReferencesResolveConcurrently(t *testing.T) {
	t.Parallel()
	r := &markerResolver{delay: 100 * time.Millisecond}
	m := newMat(t, MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r})
	byID := map[ids.RegistryID]*registry.Registry{}
	for i := range 8 {
		reg := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr(string(rune('a' + i))))}}
		byID[reg.ID] = reg
	}
	start := time.Now()
	m.Registries(context.Background(), ids.New[ids.GatewayKind](), byID)
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatalf("8 references took %v; they must be read concurrently", took)
	}
}

// selfNotifyingResolver reports a change of the payload it is resolving, as
// a background refresh finishing mid-load would.
type selfNotifyingResolver struct{ markerResolver }

func (r *selfNotifyingResolver) Resolve(ctx context.Context, ref domain.Ref) (string, error) {
	r.fire([]domain.Ref{{Store: ref.Store, Path: ref.Path, Version: ref.Version}})
	return r.markerResolver.Resolve(ctx, ref)
}

func TestChangeDuringTheFirstLoadInvalidatesIt(t *testing.T) {
	t.Parallel()
	inv := &invalidations{}
	r := &selfNotifyingResolver{}
	m := newMat(t, MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r, Invalidate: inv.add})
	gw := ids.New[ids.GatewayKind]()
	reg := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("k"))}}
	m.Registries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{reg.ID: reg})
	if got := inv.list(); len(got) != 1 || got[0] != gw {
		t.Fatalf("a change during the first load must invalidate it, got %v", got)
	}
}

func TestNoStoresSkipsTheGatewayLookup(t *testing.T) {
	t.Parallel()
	finder := &gatewayFinder{gw: &gateway.Gateway{}}
	m := newMat(t, MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityHybrid, Gateways: finder})
	reg := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("k"))}}
	out := m.Registries(context.Background(), ids.New[ids.GatewayKind](), map[ids.RegistryID]*registry.Registry{reg.ID: reg})
	if !out[reg.ID].CredentialUnavailable() || finder.calls.Load() != 0 {
		t.Fatalf("unavailable %v, gateway reads %d", out[reg.ID].CredentialUnavailable(), finder.calls.Load())
	}
}

func TestChangesInvalidateTheGatewaysThatUsedThem(t *testing.T) {
	t.Parallel()
	r := &markerResolver{}
	inv := &invalidations{}
	m := newMat(t, MaterializerConfig{Enabled: true, Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r, Invalidate: inv.add})
	gwA, gwB := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	regA := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("shared#a"))}}
	regB := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("other"))}}
	m.Registries(context.Background(), gwA, map[ids.RegistryID]*registry.Registry{regA.ID: regA})
	m.Registries(context.Background(), gwB, map[ids.RegistryID]*registry.Registry{regB.ID: regB})

	r.fire([]domain.Ref{{Store: "vault", Path: "ai/shared"}})
	if got := inv.list(); len(got) != 1 || got[0] != gwA {
		t.Fatalf("invalidated %v, want only gateway A", got)
	}

	plain := &registry.Registry{ID: regA.ID, LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth("sk")}}
	m.Registries(context.Background(), gwA, map[ids.RegistryID]*registry.Registry{plain.ID: plain})
	r.fire([]domain.Ref{{Store: "vault", Path: "ai/shared"}})
	if got := inv.list(); len(got) != 1 {
		t.Fatalf("a gateway that stopped using a payload was invalidated again: %v", got)
	}

	m.StoresChanged([]string{"vault"})
	if got := inv.list(); len(got) != 2 || got[1] != gwB {
		t.Fatalf("after the store changed: %v", got)
	}
}
