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

package secretstore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

var now = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

type health []domain.Status

func (h health) Statuses() []domain.Status { return h }

type instances []dataplane.Instance

func (in instances) ListInstances(context.Context, string) ([]dataplane.Instance, error) {
	return in, nil
}

func gw(dataPlane string) *gateway.Gateway {
	return &gateway.Gateway{ID: ids.New[ids.GatewayKind](), Entitlements: gateway.Entitlements{DataPlane: dataPlane}}
}

func live(id string, accepts bool, stores ...domain.Status) dataplane.Instance {
	return dataplane.Instance{ID: id, State: "connected", LastSeen: now, AcceptsSecretRefs: accepts, SecretStores: stores}
}

func vault(state domain.State, gateways ...ids.GatewayID) domain.Status {
	return domain.Status{Name: "corp-vault", Type: domain.TypeHashiCorpVault, AllowedPaths: []string{"ai/"}, State: state, Gateways: gateways}
}

func resolver(cfg SourceConfig) SourceResolver {
	cfg.Now = func() time.Time { return now }
	return NewSourceResolver(cfg)
}

func TestSourceOnNeuralTrustControlPlane(t *testing.T) {
	t.Parallel()
	r := resolver(SourceConfig{Eligibility: domain.EligibilityHybrid, Instances: instances{live("dp-1", true, vault(domain.StateOK))}})
	hosted, _ := r.Source(context.Background(), gw(""))
	dedicated, _ := r.Source(context.Background(), gw(gateway.DataPlaneDedicated))
	hybrid, _ := r.Source(context.Background(), gw(gateway.DataPlaneHybrid))
	if hosted.Supported || dedicated.Supported {
		t.Fatal("hosted and dedicated gateways must not be supported")
	}
	if !hybrid.Supported || hybrid.Kind != KindDataPlane || len(hybrid.Stores) != 1 || hybrid.Live != 1 {
		t.Fatalf("hybrid = %+v", hybrid)
	}
}

func TestSourceOnSelfHostedControlPlane(t *testing.T) {
	t.Parallel()
	g := gw("")
	other := ids.New[ids.GatewayKind]()
	r := resolver(SourceConfig{Eligibility: domain.EligibilityAll, AdminInstance: "admin-0",
		Health: health{vault(domain.StateOK), {Name: "team-b", Type: domain.TypeEnv, AllowedPaths: []string{"*"}, Gateways: []ids.GatewayID{other}}}})
	src, err := r.Source(context.Background(), g)
	if err != nil || !src.Supported || src.Kind != KindControlPlane {
		t.Fatalf("source %+v, %v", src, err)
	}
	if len(src.Stores) != 1 || src.Stores[0].Name != "corp-vault" || src.Stores[0].Instances[0].InstanceID != "admin-0" {
		t.Fatalf("stores %+v: another team's store must be filtered out", src.Stores)
	}
}

func TestDataPlaneAggregation(t *testing.T) {
	t.Parallel()
	g := gw(gateway.DataPlaneHybrid)
	stale := live("dp-gone", true, vault(domain.StateUnavailable))
	stale.LastSeen = now.Add(-time.Hour)
	odd := vault(domain.StateOK)
	odd.AllowedPaths = []string{"other/"}
	r := resolver(SourceConfig{Eligibility: domain.EligibilityHybrid, Instances: instances{
		live("dp-1", true, vault(domain.StateOK)),
		live("dp-2", true, vault(domain.StateAuthFailed)),
		live("dp-3", false),
		stale,
	}})
	src, _ := r.Source(context.Background(), g)
	if src.Live != 3 || len(src.TooOld) != 1 || src.TooOld[0].InstanceID != "dp-3" {
		t.Fatalf("live %d too old %+v", src.Live, src.TooOld)
	}
	if st := src.Stores[0]; st.Status != StatusDegraded || len(st.Instances) != 2 || !st.Consistent {
		t.Fatalf("store %+v", st)
	}
	r2 := resolver(SourceConfig{Eligibility: domain.EligibilityHybrid, Instances: instances{
		live("dp-1", true, vault(domain.StateOK)), live("dp-2", true, odd),
	}})
	if src, _ := r2.Source(context.Background(), g); src.Stores[0].Consistent || src.Stores[0].Status != StatusOK {
		t.Fatalf("instances that disagree must be flagged: %+v", src.Stores[0])
	}

	for _, order := range []instances{
		{live("dp-1", true, vault(domain.StateOK)), live("dp-2", true, odd)},
		{live("dp-2", true, odd), live("dp-1", true, vault(domain.StateOK))},
	} {
		r3 := resolver(SourceConfig{Eligibility: domain.EligibilityHybrid, Instances: order})
		src, _ := r3.Source(context.Background(), g)
		st := src.Stores[0]
		if !st.AllowsPath("other/x") || !st.AllowsPath(vault(domain.StateOK).AllowedPaths[0]+"x") || st.AllowsPath("nobody/x") {
			t.Fatalf("a path some instance allows must be admitted whatever the order: %+v", st)
		}
	}
}

type fixedSource struct{ src Source }

func (f fixedSource) Source(context.Context, *gateway.Gateway) (Source, error) { return f.src, nil }

type gateways struct{ g *gateway.Gateway }

func (g gateways) FindByID(context.Context, ids.GatewayID) (*gateway.Gateway, error) { return g.g, nil }

func withKey(key string) *registry.Registry {
	return &registry.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registry.LLMTarget{Auth: registry.NewAPIKeyAuth(key)}}
}

func TestValidator(t *testing.T) {
	t.Parallel()
	g := gw(gateway.DataPlaneHybrid)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	control := Source{Supported: true, Kind: KindControlPlane, Stores: []StoreView{
		{Name: "corp-vault", Type: domain.TypeHashiCorpVault, AllowedPaths: []string{"ai/"}},
		{Name: "env", Type: domain.TypeEnv, AllowedPaths: []string{"*"}},
	}}
	dp := Source{Supported: true, Kind: KindDataPlane, Live: 1, Stores: control.Stores}
	may := Caller{MayReference: true}
	ref := "secret://corp-vault/ai/openai#key"
	tests := []struct {
		name   string
		src    Source
		caller Caller
		key    string
		want   error
	}{
		{"literal", control, Caller{}, "sk-live", nil},
		{"embedded", control, may, "Bearer " + ref, refdomain.ErrInvalidReference},
		{"malformed", control, may, "secret://corp-vault", refdomain.ErrInvalidReference},
		{"not supported", Source{}, may, ref, refdomain.ErrReferencesNotSupported},
		{"missing scope", control, Caller{}, ref, refdomain.ErrMissingScope},
		{"unknown store", control, may, "secret://corp-valt/ai/openai#key", refdomain.ErrUnknownStore},
		{"path", control, may, "secret://corp-vault/payments/db", refdomain.ErrPathNotAllowed},
		{"env version", control, may, "secret://env/TG_SECRET_X?version=2", refdomain.ErrInvalidReference},
		{"ok control plane", control, may, ref, nil},
		{"ok data plane", dp, may, ref, nil},
		{"unverified", Source{Supported: true, Kind: KindDataPlane}, may, ref, refdomain.ErrStoreUnverified},
		{"unverified opt-in", Source{Supported: true, Kind: KindDataPlane}, Caller{MayReference: true, AllowUnverified: true}, ref, nil},
		{"too old", Source{Supported: true, Kind: KindDataPlane, Live: 2, TooOld: []InstanceView{{InstanceID: "dp-2"}}, Stores: control.Stores}, may, ref, refdomain.ErrDataPlaneTooOld},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := NewRegistryValidator(fixedSource{tt.src}, gateways{g}, logger)
			_, err := v.ValidateRegistry(WithCaller(context.Background(), tt.caller), withKey(tt.key), nil)
			if (tt.want == nil) != (err == nil) || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValidatorAcceptsEchoedReferences(t *testing.T) {
	t.Parallel()
	ref := "secret://corp-vault/ai/openai#key"
	previous := appsecretref.StoredOf(withKey(ref))
	v := NewRegistryValidator(fixedSource{Source{}}, gateways{gw("")}, nil)
	if _, err := v.ValidateRegistry(context.Background(), withKey(ref), previous); err != nil {
		t.Fatalf("an echoed reference must be kept even where references are no longer supported: %v", err)
	}
	if _, err := v.ValidateRegistry(context.Background(), withKey("secret://corp-vault/ai/other"), previous); !errors.Is(err, refdomain.ErrReferencesNotSupported) {
		t.Fatalf("a changed reference: %v", err)
	}
}

func TestValidatorEmbeddedValues(t *testing.T) {
	t.Parallel()
	embedded := "Bearer secret://corp-vault/ai/openai"
	on := NewRegistryValidator(fixedSource{Source{Supported: true, Kind: KindControlPlane}}, gateways{gw("")}, nil)
	if _, err := on.ValidateRegistry(context.Background(), withKey(embedded), nil); !errors.Is(err, refdomain.ErrInvalidReference) {
		t.Fatalf("a new embedded value: %v", err)
	}
	if _, err := on.ValidateRegistry(context.Background(), withKey(embedded), appsecretref.StoredOf(withKey(embedded))); err != nil {
		t.Fatalf("an echoed embedded value must not block unrelated edits: %v", err)
	}
	agent := &registry.Registry{ID: ids.New[ids.RegistryKind](), A2ATarget: &registry.A2ATarget{
		URL: "https://agent", Headers: map[string]string{"X-Agent": embedded},
	}}
	if _, err := on.ValidateRegistry(context.Background(), agent, nil); !errors.Is(err, refdomain.ErrInvalidReference) {
		t.Fatalf("an A2A header embedding a reference: %v", err)
	}
}

type logSink struct{ lines []string }

func (l *logSink) Write(p []byte) (int, error) {
	l.lines = append(l.lines, string(p))
	return len(p), nil
}

func TestAuditRunsAfterTheWriteAndCoversRemovals(t *testing.T) {
	t.Parallel()
	sink := &logSink{}
	logger := slog.New(slog.NewTextHandler(sink, nil))
	control := Source{Supported: true, Kind: KindControlPlane, Stores: []StoreView{{Name: "corp-vault", AllowedPaths: []string{"ai/"}}}}
	v := NewRegistryValidator(fixedSource{control}, gateways{gw("")}, logger)
	ctx := WithCaller(context.Background(), Caller{MayReference: true, Actor: "ana@example.com"})
	audit, err := v.ValidateRegistry(ctx, withKey("secret://corp-vault/ai/openai#key"), nil)
	if err != nil || len(sink.lines) != 0 {
		t.Fatalf("nothing is logged before the write: %v %v", err, sink.lines)
	}
	audit()
	if len(sink.lines) != 1 || !strings.Contains(sink.lines[0], "action=set") || !strings.Contains(sink.lines[0], "actor=ana@example.com") || !strings.Contains(sink.lines[0], "store=corp-vault") {
		t.Fatalf("audit = %v", sink.lines)
	}
	audit, err = v.ValidateRegistry(ctx, withKey("sk-literal"), appsecretref.StoredOf(withKey("secret://corp-vault/ai/openai#key")))
	if err != nil {
		t.Fatal(err)
	}
	audit()
	if last := sink.lines[len(sink.lines)-1]; !strings.Contains(last, "action=removed") || strings.Contains(last, "sk-literal") {
		t.Fatalf("removal audit = %q", last)
	}
}

type pagedRegistries struct{ all []*registry.Registry }

func (p pagedRegistries) List(_ context.Context, f registry.ListFilter) ([]*registry.Registry, int, error) {
	start := (f.Page - 1) * f.Size
	if start >= len(p.all) {
		return nil, len(p.all), nil
	}
	end := min(start+f.Size, len(p.all))
	return p.all[start:end], len(p.all), nil
}

func TestUsages(t *testing.T) {
	t.Parallel()
	var all []*registry.Registry
	for i := range 250 {
		r := withKey("sk")
		if i%50 == 0 {
			r = withKey("secret://corp-vault/ai/k" + strings.Repeat("x", i%3))
		}
		r.Name = "r"
		all = append(all, r)
	}
	all = append(all, &registry.Registry{ID: ids.New[ids.RegistryKind](), Name: "mcp", MCPTarget: &registry.MCPTarget{Headers: map[string]string{"X": "secret://env/TG_SECRET_X"}}})
	gwID := ids.New[ids.GatewayKind]()
	auths := func(_ context.Context, gw ids.GatewayID) ([]NamedRefs, error) {
		if gw != gwID {
			t.Errorf("the lister must read the asked gateway")
		}
		return []NamedRefs{{Name: "okta", EntityRefs: appsecretref.EntityRefs{
			GatewayID: gw, Entity: refdomain.EntityAuth, ID: "a1",
			Uses: []appsecretref.Use{{Path: []string{"config", "oauth2", "client_secret"}, Raw: "secret://env/TG_SECRET_OKTA"}},
		}}}, nil
	}
	got, err := NewUsagesFinder(pagedRegistries{all}, auths).Usages(context.Background(), gwID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["corp-vault"]) != 5 || len(got["env"]) != 2 {
		t.Fatalf("usages = %+v", got)
	}
	if got["env"][0].Entity != "auth" || got["env"][0].Field != "config.oauth2.client_secret" || got["env"][1].Field != "mcp_target.headers.X" {
		t.Fatalf("env usages = %+v, want sorted by entity", got["env"])
	}
}

func TestValidatorRechecksReferencesWhenTheDestinationChanges(t *testing.T) {
	t.Parallel()
	control := Source{Supported: true, Kind: KindControlPlane, Stores: []StoreView{{Name: "corp-vault", Type: domain.TypeHashiCorpVault, AllowedPaths: []string{"ai/"}}}}
	v := NewRegistryValidator(fixedSource{control}, gateways{gw("")}, nil)
	ref := "secret://corp-vault/ai/openai#key"
	stored := withKey(ref)
	stored.LLMTarget.Provider = "openai"
	stored.LLMTarget.ProviderOptions = map[string]any{"base_url": "https://api.openai.com/v1"}
	previous := appsecretref.StoredOf(stored)
	noScope := WithCaller(context.Background(), Caller{})

	same := withKey(ref)
	same.LLMTarget.Provider = "openai"
	same.LLMTarget.ProviderOptions = map[string]any{"base_url": "https://api.openai.com/v1", "headers": map[string]any{"X": "y"}}
	if _, err := v.ValidateRegistry(noScope, same, previous); err != nil {
		t.Fatalf("an echoed reference with the same destination needs no scope: %v", err)
	}
	moved := withKey(ref)
	moved.LLMTarget.Provider = "openai"
	moved.LLMTarget.ProviderOptions = map[string]any{"base_url": "https://attacker.example/v1"}
	if _, err := v.ValidateRegistry(noScope, moved, previous); !errors.Is(err, refdomain.ErrMissingScope) {
		t.Fatalf("a new base_url must re-check the echoed reference: %v", err)
	}
	if _, err := v.ValidateRegistry(WithCaller(context.Background(), Caller{MayReference: true}), moved, previous); err != nil {
		t.Fatalf("a caller with the scope may move it: %v", err)
	}
}

func TestValidatorRefusesADestinationOutsideTheList(t *testing.T) {
	t.Parallel()
	g := gw(gateway.DataPlaneHybrid)
	locked := func(destinations ...string) domain.Status {
		st := vault(domain.StateOK)
		st.AllowedDestinations = destinations
		return st
	}
	src := dataPlaneSource(g.ID, []dataplane.Instance{
		live("dp-1", true, locked("api.openai.com")),
		live("dp-2", true, locked("api.openai.com", "*.example.com")),
	}, now)
	if src.Stores[0].Consistent {
		t.Fatal("instances that disagree on allowed destinations are not consistent")
	}
	v := NewRegistryValidator(fixedSource{src}, gateways{g}, nil)
	ctx := WithCaller(context.Background(), Caller{MayReference: true})
	ref := "secret://corp-vault/ai/openai#key"

	allowed := withKey(ref)
	allowed.GatewayID, allowed.LLMTarget.Provider = g.ID, "openai"
	if _, err := v.ValidateRegistry(ctx, allowed, nil); err != nil {
		t.Fatalf("a host every instance allows: %v", err)
	}
	partly := withKey(ref)
	partly.GatewayID, partly.LLMTarget.Provider = g.ID, "openai"
	partly.LLMTarget.ProviderOptions = map[string]any{"base_url": "https://llm.example.com/v1"}
	if _, err := v.ValidateRegistry(ctx, partly, nil); !errors.Is(err, refdomain.ErrDestinationNotAllowed) {
		t.Fatalf("a host one instance refuses must be refused: %v", err)
	}
}

func TestUsageStatesFollowTheReportedOutcome(t *testing.T) {
	t.Parallel()
	g := gw(gateway.DataPlaneHybrid)
	report := func(class domain.Class, path string) dataplane.Instance {
		in := live("dp-"+path+string(class), true, vault(domain.StateOK))
		in.SecretRefs = domain.RefHealth{Total: 1, Outcomes: []domain.RefOutcome{{
			GatewayID: g.ID, Entity: "registry", ID: "r1", Field: "llm_target.auth.api_key.api_key", Store: "corp-vault", Path: path, Class: class,
		}}}
		return in
	}
	usage := Usage{Entity: "registry", ID: "r1", Field: "llm_target.auth.api_key.api_key", Reference: "secret://corp-vault/ai/openai#key"}

	for name, tt := range map[string]struct {
		instances []dataplane.Instance
		state     string
		class     domain.Class
	}{
		"resolved":           {[]dataplane.Instance{report("", "ai/openai")}, RefStateOK, ""},
		"failing on one":     {[]dataplane.Instance{report("", "ai/openai"), report(domain.ClassAccessDenied, "ai/openai")}, RefStateFailing, domain.ClassAccessDenied},
		"never resolved":     {[]dataplane.Instance{live("dp-1", true, vault(domain.StateOK))}, RefStateNotReported, ""},
		"an older reference": {[]dataplane.Instance{report("", "ai/old")}, RefStateNotReported, ""},
	} {
		src := dataPlaneSource(g.ID, tt.instances, now)
		uses := map[string][]Usage{"corp-vault": {usage}}
		src.Annotate(g.ID, uses)
		if got := uses["corp-vault"][0]; got.State != tt.state || got.ErrorClass != string(tt.class) {
			t.Errorf("%s: state = %q %q, want %q %q", name, got.State, got.ErrorClass, tt.state, tt.class)
		}
	}
}
