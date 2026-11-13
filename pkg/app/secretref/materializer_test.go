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

	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"

	"github.com/NeuralTrust/TrustGate/pkg/domain/auth"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"

	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"

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
			Auth:    &registry.MCPAuth{Mode: registry.MCPAuthModeStatic, Header: "Authorization", Value: refStr("mv#v"), ClientSecret: refStr("mcs#v"), TokenURL: "https://idp/token"},
		},
		A2ATarget: &registry.A2ATarget{
			URL:     "https://agent",
			Headers: map[string]string{"X-Agent": refStr("ah#v"), "X-Plain": "plain"},
			Auth:    &registry.MCPAuth{Mode: registry.MCPAuthModeStatic, Header: "X-Key", Value: refStr("av#v"), ClientSecret: refStr("acs#v"), TokenURL: "https://idp/token"},
			CloudAuth: &registry.A2ACloudAuth{
				AWS:   &registry.A2AAWSAuth{AWSAuth: registry.AWSAuth{AccessKeyID: refStr("caa#k"), SecretAccessKey: refStr("caa#s"), SessionToken: refStr("caa#t")}},
				Azure: &registry.AzureAuth{ClientSecret: refStr("caz#s")},
				GCP:   &registry.A2AGCPAuth{ServiceAccountJSON: refStr("cag")},
			},
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
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}})
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
	declared := 0
	for _, l := range domain.Locations {
		if l.Entity == domain.EntityRegistry {
			declared++
		}
	}
	if resolved != declared {
		t.Fatalf("resolved %d locations, the fixture must cover all %d declared registry ones", resolved, declared)
	}
}

func TestFastPathReturnsTheInput(t *testing.T) {
	plain := everyLocation()
	plain.LLMTarget.Auth = registry.NewAPIKeyAuth("sk-live")
	plain.LLMTarget.ProviderOptions = map[string]any{"headers": map[string]string{"X": "y"}}
	plain.MCPTarget.Headers = map[string]string{"X": "y"}
	plain.MCPTarget.Auth.Value, plain.MCPTarget.Auth.ClientSecret = "v", ""
	plain.A2ATarget.Headers = map[string]string{"X": "y"}
	plain.A2ATarget.Auth.Value, plain.A2ATarget.Auth.ClientSecret = "v", ""
	plain.A2ATarget.CloudAuth.AWS.SecretAccessKey = "aws-secret"
	plain.A2ATarget.CloudAuth.AWS.AccessKeyID, plain.A2ATarget.CloudAuth.AWS.SessionToken = "", ""
	plain.A2ATarget.CloudAuth.Azure.ClientSecret = "azure-secret"
	plain.A2ATarget.CloudAuth.GCP.ServiceAccountJSON = "{}"
	byID := map[ids.RegistryID]*registry.Registry{plain.ID: plain}
	m := newMat(t, MaterializerConfig{})
	gw := ids.New[ids.GatewayKind]()
	if got := m.GatewayRegistries(context.Background(), gw, byID); reflect.ValueOf(got).Pointer() != reflect.ValueOf(byID).Pointer() {
		t.Fatal("without references the input map must be returned as is")
	}
	allocs := testing.AllocsPerRun(100, func() { m.GatewayRegistries(context.Background(), gw, byID) })
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
		"no store file":       {MaterializerConfig{Eligibility: secretstore.EligibilityAll}, refStr("k")},
		"hosted gateway":      {MaterializerConfig{Eligibility: secretstore.EligibilityHybrid, Gateways: hosted, Catalog: storeCatalog(), Resolver: &markerResolver{}}, refStr("k")},
		"gateway unreadable":  {MaterializerConfig{Eligibility: secretstore.EligibilityHybrid, Gateways: &gatewayFinder{err: errors.New("db")}, Catalog: storeCatalog(), Resolver: &markerResolver{}}, refStr("k")},
		"not in allowlist":    {MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(other), Resolver: &markerResolver{}}, refStr("k")},
		"path not allowed":    {MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}}, "secret://vault/payments/db"},
		"unknown store":       {MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}}, "secret://nope/ai/k"},
		"malformed reference": {MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}}, "secret://vault"},
		"store failure":       {MaterializerConfig{Eligibility: secretstore.EligibilityHybrid, Gateways: hybrid, Catalog: storeCatalog(), Resolver: &markerResolver{err: secretstore.ErrNotFound}}, refStr("k")},
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
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityHybrid, Gateways: finder, Catalog: storeCatalog(), Resolver: &markerResolver{}})
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
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r})
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
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r, Invalidate: inv.add})
	gw := ids.New[ids.GatewayKind]()
	reg := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("k"))}}
	m.GatewayRegistries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{reg.ID: reg})
	if got := inv.list(); len(got) != 1 || got[0] != gw {
		t.Fatalf("a change during the first load must invalidate it, got %v", got)
	}
}

func TestNoStoresSkipsTheGatewayLookup(t *testing.T) {
	t.Parallel()
	finder := &gatewayFinder{gw: &gateway.Gateway{}}
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityHybrid, Gateways: finder})
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
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r, Invalidate: inv.add})
	gwA, gwB := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	regA := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("shared#a"))}}
	regB := &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("other"))}}
	m.GatewayRegistries(context.Background(), gwA, map[ids.RegistryID]*registry.Registry{regA.ID: regA})
	m.GatewayRegistries(context.Background(), gwB, map[ids.RegistryID]*registry.Registry{regB.ID: regB})

	r.fire([]domain.Ref{{Store: "vault", Path: "ai/shared"}})
	if got := inv.list(); len(got) != 1 || got[0] != gwA {
		t.Fatalf("invalidated %v, want only gateway A", got)
	}

	plain := &registry.Registry{ID: regA.ID, LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth("sk")}}
	m.GatewayRegistries(context.Background(), gwA, map[ids.RegistryID]*registry.Registry{plain.ID: plain})
	r.fire([]domain.Ref{{Store: "vault", Path: "ai/shared"}})
	if got := inv.list(); len(got) != 1 {
		t.Fatalf("a gateway that stopped using a payload was invalidated again: %v", got)
	}

	m.StoresChanged([]string{"vault"})
	if got := inv.list(); len(got) != 2 || got[1] != gwB {
		t.Fatalf("after the store changed: %v", got)
	}
}

// TestPartialReadersKeepTheGatewayIndex reads one registry of an indexed
// gateway the way the runtime finder, the classifier, the Store scoper and a
// refresh do, and requires that a change still reaches the gateway.
func TestPartialReadersKeepTheGatewayIndex(t *testing.T) {
	t.Parallel()
	r := &markerResolver{}
	inv := &invalidations{}
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r, Invalidate: inv.add})
	gw := ids.New[ids.GatewayKind]()
	referenced := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("shared"))}}
	literal := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth("sk")}}
	m.GatewayRegistries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{referenced.ID: referenced, literal.ID: literal})

	m.Registries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{literal.ID: literal})
	other := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(refStr("other"))}}
	m.Registries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{other.ID: other})
	copied := m.Registries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{referenced.ID: referenced})[referenced.ID]
	m.Refresh(context.Background(), copied)

	r.fire([]domain.Ref{{Store: "vault", Path: "ai/shared"}})
	if got := inv.list(); len(got) != 1 || got[0] != gw {
		t.Fatalf("a partial read dropped the gateway from the index: invalidated %v", got)
	}
}

func TestMaterializeDoesNotKeepAFailedEligibilityRead(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{
		Provider: "openai", Auth: registry.NewAPIKeyAuth(refStr("k#a")),
	}}
	inv := &invalidations{}
	m := newMat(t, MaterializerConfig{
		Eligibility: secretstore.EligibilityHybrid, Catalog: storeCatalog(), Resolver: &markerResolver{},
		Gateways: &gatewayFinder{err: errors.New("read timed out")}, Invalidate: inv.add,
	})
	out := m.GatewayRegistries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{reg.ID: reg})
	if !out[reg.ID].CredentialUnavailable() {
		t.Fatal("without the gateway's eligibility the reference must stay unresolved")
	}
	if got := inv.list(); len(got) != 1 || got[0] != gw {
		t.Fatalf("invalidations = %v; the load must be dropped so the next request reads the gateway again", got)
	}
}

// The typed accessors and the declared Locations must name the same fields:
// a location without an accessor would be validated but never resolved, and
// an accessor without a location would resolve a field nobody may write.
func TestRegistryAccessorsMatchDeclaredLocations(t *testing.T) {
	t.Parallel()
	reg := everyLocation()
	if !registryHasRef(reg) {
		t.Fatal("registryHasRef misses a declared location")
	}
	slots := registrySlots(reg)
	for _, s := range slots {
		if !domain.IsLocation(domain.EntityRegistry, s.path) {
			t.Errorf("accessor path %v is not a declared location", s.path)
		}
	}
	for _, l := range domain.Locations {
		if l.Entity != domain.EntityRegistry {
			continue
		}
		covered := false
		for _, s := range slots {
			if l.Matches(domain.EntityRegistry, s.path) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("declared location %v has no accessor", l.Path)
		}
	}
}

func TestStoresChangedDropsDeletedGatewaysFromTheIndex(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	reg := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{
		Provider: "openai", Auth: registry.NewAPIKeyAuth(refStr("k#a")),
	}}
	finder := &gatewayFinder{gw: &gateway.Gateway{ID: gw}}
	inv := &invalidations{}
	m := newMat(t, MaterializerConfig{
		Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{},
		Gateways: finder, Invalidate: inv.add,
	})
	m.GatewayRegistries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{reg.ID: reg})

	finder.gw, finder.err = nil, gateway.ErrNotFound
	m.StoresChanged([]string{"vault"})
	if got := inv.list(); len(got) != 0 {
		t.Fatalf("invalidations = %v; a deleted gateway has no data to drop", got)
	}
	impl := m.(*materializer)
	impl.mu.Lock()
	n := len(impl.byGateway) + len(impl.byPayload)
	impl.mu.Unlock()
	if n != 0 {
		t.Fatal("a deleted gateway must leave the index")
	}
}

func TestValuesResolveAndIndexPerSource(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	r := &markerResolver{}
	inv := &invalidations{}
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: r, Invalidate: inv.add})

	got := m.Values(context.Background(), gw, SourceConsumers, []Use{
		{Path: []string{"lb_config", "embedding", "auth", "api_key"}, Raw: refStr("emb#k")},
		{Path: []string{"x"}, Raw: "secret://vault/payments/db"},
	})
	if got[0].Err != nil || got[0].Value == "" || got[0].Value == refStr("emb#k") {
		t.Fatalf("resolved = %+v", got[0])
	}
	if got[1].Err == nil || got[1].Value != "" {
		t.Fatalf("a disallowed path must come back empty with its error: %+v", got[1])
	}

	in := &registry.Registry{ID: ids.New[ids.RegistryKind](), GatewayID: gw, LLMTarget: &registry.LLMTarget{Provider: "openai", Auth: registry.NewAPIKeyAuth(refStr("k#a"))}}
	m.GatewayRegistries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{in.ID: in})
	m.GatewayRegistries(context.Background(), gw, map[ids.RegistryID]*registry.Registry{})

	emb, _, _ := domain.Parse(refStr("emb"))
	r.fire([]domain.Ref{emb})
	if got := inv.list(); len(got) != 1 || got[0] != gw {
		t.Fatalf("invalidations = %v; dropping the registries must keep what the consumers use", got)
	}
}

func embeddingConsumer(gw ids.GatewayID, apiKey string) *consumer.Consumer {
	return &consumer.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gw, LBConfig: &consumer.LBConfig{
		EmbeddingConfig: &registry.EmbeddingConfig{Provider: "openai", Model: "text-embedding-3-small", Auth: &registry.APIKeyAuth{APIKey: apiKey}},
	}}
}

func TestGatewayConsumersResolveTheEmbeddingCredential(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}})
	plain := embeddingConsumer(gw, "sk-plain")
	ref := embeddingConsumer(gw, refStr("emb#k"))
	bad := embeddingConsumer(gw, "secret://vault/payments/k")

	out := GatewayConsumers(context.Background(), m, gw, []*consumer.Consumer{plain, ref, bad, nil})
	if out[0] != plain || out[3] != nil {
		t.Fatal("consumers without references are returned as they are")
	}
	if got := out[1].LBConfig.EmbeddingConfig.Auth.APIKey; got == "" || got == refStr("emb#k") {
		t.Fatalf("resolved key = %q", got)
	}
	if ref.LBConfig.EmbeddingConfig.Auth.APIKey != refStr("emb#k") {
		t.Fatal("the input consumer was modified")
	}
	if out[2].LBConfig.EmbeddingConfig.Auth.APIKey != "" {
		t.Fatal("an unresolved reference is left empty, never sent")
	}
}

func TestConsumerAccessorsMatchDeclaredLocations(t *testing.T) {
	t.Parallel()
	c := embeddingConsumer(ids.New[ids.GatewayKind](), refStr("a"))
	c.LBConfig.EmbeddingConfig.Auth.HeaderValue = refStr("b")
	uses := ConsumerRefs(c).Uses
	covered := map[string]bool{}
	for _, u := range uses {
		if !domain.IsLocation(domain.EntityConsumer, u.Path) {
			t.Errorf("accessor path %v is not a declared location", u.Path)
		}
		covered[strings.Join(u.Path, ".")] = true
	}
	for _, l := range domain.Locations {
		if l.Entity == domain.EntityConsumer && !covered[strings.Join(l.Path, ".")] {
			t.Errorf("declared location %v has no accessor", l.Path)
		}
	}
}

func TestGatewayPoliciesResolvePluginCredentials(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}})
	guard := &policy.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gw, Slug: "bedrock_guardrail", Settings: map[string]any{
		"credentials":  map[string]any{"access_key_id": refStr("aws#id"), "secret_access_key": "secret://vault/payments/sk"},
		"guardrail_id": "g-1",
	}}
	plain := &policy.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gw, Slug: "rate_limiter", Settings: map[string]any{"limit": 10}}
	paths := func(p *policy.Policy) ([]string, []string) {
		if p.Slug == "bedrock_guardrail" {
			return []string{"credentials.access_key_id", "credentials.secret_access_key"}, []string{"bedrock-runtime.eu-west-1.amazonaws.com"}
		}
		return nil, nil
	}

	out := GatewayPolicies(context.Background(), m, gw, []*policy.Policy{guard, plain}, paths)
	if out[1] != plain {
		t.Fatal("a policy without references is returned as it is")
	}
	creds := out[0].Settings["credentials"].(map[string]any)
	if creds["access_key_id"] == refStr("aws#id") || creds["access_key_id"] == "" {
		t.Fatalf("access_key_id = %v", creds["access_key_id"])
	}
	if creds["secret_access_key"] != "" {
		t.Fatal("a reference outside the allowed paths is left empty")
	}
	if guard.Settings["credentials"].(map[string]any)["access_key_id"] != refStr("aws#id") {
		t.Fatal("the input policy was modified")
	}
	if out[0].Settings["guardrail_id"] != "g-1" {
		t.Fatal("other settings are kept")
	}
}

func TestAuthAccessorsMatchDeclaredLocations(t *testing.T) {
	t.Parallel()
	a := &auth.Auth{Config: auth.Config{OAuth2: &auth.OAuth2Config{ClientSecret: refStr("c"), ExchangeClientSecret: refStr("x")}}}
	covered := map[string]bool{}
	for _, u := range AuthRefs(a).Uses {
		if !domain.IsLocation(domain.EntityAuth, u.Path) {
			t.Errorf("accessor path %v is not a declared location", u.Path)
		}
		covered[strings.Join(u.Path, ".")] = true
	}
	for _, l := range domain.Locations {
		if l.Entity == domain.EntityAuth && !covered[strings.Join(l.Path, ".")] {
			t.Errorf("declared location %v has no accessor", l.Path)
		}
	}
	out := GatewayAuths(context.Background(), newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}}),
		ids.New[ids.GatewayKind](), SourceAuths, []*auth.Auth{a})
	if out[0] == a || out[0].Config.OAuth2.ClientSecret == refStr("c") || a.Config.OAuth2.ClientSecret != refStr("c") {
		t.Fatal("the copy carries the resolved value and the input is untouched")
	}
}

func TestGatewayAccessorsMatchDeclaredLocations(t *testing.T) {
	t.Parallel()
	gw := &gateway.Gateway{ID: ids.New[ids.GatewayKind](), Telemetry: &telemetry.Telemetry{Exporters: []telemetry.ExporterConfig{
		{Name: "otel", Type: "otlp", Settings: map[string]any{"headers": map[string]any{"Authorization": refStr("h")}}},
		{Name: "pg", Type: "postgres", Settings: map[string]any{"dsn": refStr("d")}},
	}}}
	refs := GatewayRefs(gw)
	if len(refs.Uses) != 2 {
		t.Fatalf("uses = %v", refs.Uses)
	}
	for _, u := range refs.Uses {
		if !domain.IsLocation(domain.EntityGateway, u.Path) {
			t.Errorf("accessor path %v is not a declared location", u.Path)
		}
	}
	m := newMat(t, MaterializerConfig{Eligibility: secretstore.EligibilityAll, Catalog: storeCatalog(), Resolver: &markerResolver{}})
	out := GatewayExporters(context.Background(), m, gw.ID, gw.Telemetry.Exporters)
	if out[0].Settings["headers"].(map[string]any)["Authorization"] == refStr("h") || out[1].Settings["dsn"] == refStr("d") {
		t.Fatal("exporter credentials must be resolved")
	}
	if gw.Telemetry.Exporters[1].Settings["dsn"] != refStr("d") {
		t.Fatal("the gateway's exporters must not be modified")
	}
}
