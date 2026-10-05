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

package configsnapshot_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func mustGatewayID(t *testing.T, s string) ids.GatewayID {
	t.Helper()
	id, err := ids.Parse[ids.GatewayKind](s)
	if err != nil {
		t.Fatalf("parse gateway id: %v", err)
	}
	return id
}

func mustConsumerID(t *testing.T, s string) ids.ConsumerID {
	t.Helper()
	id, err := ids.Parse[ids.ConsumerKind](s)
	if err != nil {
		t.Fatalf("parse consumer id: %v", err)
	}
	return id
}

type fakeGateways struct {
	items []*gatewaydomain.Gateway
	err   error
}

func (f fakeGateways) List(_ context.Context, filter gatewaydomain.ListFilter) ([]*gatewaydomain.Gateway, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	if filter.Page > 1 {
		return nil, 0, nil
	}
	return f.items, len(f.items), nil
}

type fakeConsumers struct {
	byGateway map[string][]*consumerdomain.Consumer
	err       error
}

func (f fakeConsumers) ListByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*consumerdomain.Consumer, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byGateway[gatewayID.String()], nil
}

func (f fakeConsumers) List(_ context.Context, filter consumerdomain.ListFilter) ([]*consumerdomain.Consumer, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	if filter.Page.Number > 1 {
		return nil, 0, nil
	}
	if filter.GatewayID != (ids.GatewayID{}) {
		items := f.byGateway[filter.GatewayID.String()]
		return items, len(items), nil
	}
	items := flattenByGateway(f.byGateway)
	return items, len(items), nil
}

type fakeRegistries struct {
	byGateway    map[string][]*registrydomain.Registry
	errByGateway map[string]error
	err          error
}

func (f fakeRegistries) List(_ context.Context, filter registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	if filter.GatewayID == (ids.GatewayID{}) {
		// Bulk scan across all gateways: a corrupt row anywhere fails the
		// whole scan, mirroring the SQL repository.
		for _, err := range f.errByGateway {
			if err != nil {
				return nil, 0, err
			}
		}
		if filter.Page > 1 {
			return nil, 0, nil
		}
		items := flattenByGateway(f.byGateway)
		return items, len(items), nil
	}
	if err := f.errByGateway[filter.GatewayID.String()]; err != nil {
		return nil, 0, err
	}
	if filter.Page > 1 {
		return nil, 0, nil
	}
	items := f.byGateway[filter.GatewayID.String()]
	return items, len(items), nil
}

type fakePolicies struct {
	byGateway map[string][]*policydomain.Policy
	err       error
}

func (f fakePolicies) ListByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*policydomain.Policy, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byGateway[gatewayID.String()], nil
}

func (f fakePolicies) List(_ context.Context, filter policydomain.ListFilter) ([]*policydomain.Policy, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	if filter.Page.Number > 1 {
		return nil, 0, nil
	}
	if filter.GatewayID != (ids.GatewayID{}) {
		items := f.byGateway[filter.GatewayID.String()]
		return items, len(items), nil
	}
	items := flattenByGateway(f.byGateway)
	return items, len(items), nil
}

type fakeAuths struct {
	byGateway map[string][]*authdomain.Auth
	err       error
}

func (f fakeAuths) List(_ context.Context, filter authdomain.ListFilter) ([]*authdomain.Auth, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	if filter.Page.Number > 1 {
		return nil, 0, nil
	}
	if filter.GatewayID != (ids.GatewayID{}) {
		items := f.byGateway[filter.GatewayID.String()]
		return items, len(items), nil
	}
	items := flattenByGateway(f.byGateway)
	return items, len(items), nil
}

// flattenByGateway mirrors the SQL repos' zero-GatewayID List semantics for
// the fakes: all gateways' rows in one deterministic (key-sorted) list.
func flattenByGateway[T any](byGateway map[string][]T) []T {
	keys := make([]string, 0, len(byGateway))
	for k := range byGateway {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]T, 0)
	for _, k := range keys {
		out = append(out, byGateway[k]...)
	}
	return out
}

type fakeCatalog struct {
	providers    []catalogdomain.Provider
	modelsByCode map[string][]catalogdomain.Model
	err          error
}

func (f fakeCatalog) ListProviders(_ context.Context) ([]catalogdomain.Provider, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.providers, nil
}

func (f fakeCatalog) ListModelsByProviderCode(_ context.Context, providerCode string) ([]catalogdomain.Model, error) {
	return f.modelsByCode[providerCode], nil
}

func TestCompilerDeterministicSortedData(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")

	gateways := fakeGateways{items: []*gatewaydomain.Gateway{
		{ID: gwB},
		{ID: gwA},
	}}
	consumers := fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{
		gwA.String(): {
			{ID: mustConsumerID(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), GatewayID: gwA},
			{ID: mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), GatewayID: gwA},
		},
		gwB.String(): {
			{ID: mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"), GatewayID: gwB},
		},
	}}
	catalog := fakeCatalog{
		providers: []catalogdomain.Provider{{Code: "openai"}, {Code: "anthropic"}},
		modelsByCode: map[string][]catalogdomain.Model{
			"openai":    {{Slug: "gpt-4o"}, {Slug: "gpt-4o-mini"}},
			"anthropic": {{Slug: "claude"}},
		},
	}

	compiler := appsnapshot.NewCompiler(
		gateways,
		consumers,
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		catalog,
		nil,
	)

	snapshot, err := compiler.Compile(context.Background())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	data := snapshot.Data()

	if len(data.Gateways) != 2 || data.Gateways[0].ID != gwA || data.Gateways[1].ID != gwB {
		t.Fatalf("gateways not sorted ascending: %+v", data.Gateways)
	}
	if len(data.Consumers) != 3 {
		t.Fatalf("expected 3 consumers, got %d", len(data.Consumers))
	}
	for i := 1; i < len(data.Consumers); i++ {
		if data.Consumers[i-1].ID.String() > data.Consumers[i].ID.String() {
			t.Fatalf("consumers not sorted ascending: %+v", data.Consumers)
		}
	}
	if len(data.Providers) != 2 || data.Providers[0].Code != "anthropic" {
		t.Fatalf("providers not sorted: %+v", data.Providers)
	}
	if len(data.CatalogModels) != 3 {
		t.Fatalf("expected 3 catalog models, got %d", len(data.CatalogModels))
	}
}

func TestCompilerStableAcrossRuns(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{
			gwA.String(): {
				{ID: mustConsumerID(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), GatewayID: gwA},
				{ID: mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), GatewayID: gwA},
			},
		}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
	)

	first, err := compiler.Compile(context.Background())
	if err != nil {
		t.Fatalf("first compile: %v", err)
	}
	second, err := compiler.Compile(context.Background())
	if err != nil {
		t.Fatalf("second compile: %v", err)
	}
	if first.Data().Consumers[0].ID != second.Data().Consumers[0].ID {
		t.Fatalf("ordering not stable across runs")
	}
}

func TestCompilerToleratesNotFound(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}},
		fakeConsumers{err: commonerrors.ErrNotFound},
		fakeRegistries{err: commonerrors.ErrNotFound},
		fakePolicies{err: commonerrors.ErrNotFound},
		fakeAuths{err: commonerrors.ErrNotFound},
		fakeCatalog{err: commonerrors.ErrNotFound},
		nil,
	)

	snapshot, err := compiler.Compile(context.Background())
	if err != nil {
		t.Fatalf("compile should tolerate ErrNotFound, got: %v", err)
	}
	if len(snapshot.Data().Gateways) != 1 {
		t.Fatalf("expected 1 gateway, got %d", len(snapshot.Data().Gateways))
	}
	if len(snapshot.Data().Consumers) != 0 {
		t.Fatalf("expected 0 consumers, got %d", len(snapshot.Data().Consumers))
	}
}

func TestCompilerGatewaysNotFoundYieldsEmpty(t *testing.T) {
	compiler := appsnapshot.NewCompiler(
		fakeGateways{err: commonerrors.ErrNotFound},
		fakeConsumers{},
		fakeRegistries{},
		fakePolicies{},
		fakeAuths{},
		fakeCatalog{},
		nil,
	)
	snapshot, err := compiler.Compile(context.Background())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(snapshot.Data().Gateways) != 0 {
		t.Fatalf("expected no gateways, got %d", len(snapshot.Data().Gateways))
	}
}

func TestCompilerSkipsGatewayWithCorruptData(t *testing.T) {
	healthy := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	corrupt := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")

	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: healthy}, {ID: corrupt}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{
			healthy.String(): {{ID: mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), GatewayID: healthy}},
			corrupt.String(): {{ID: mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"), GatewayID: corrupt}},
		}},
		fakeRegistries{errByGateway: map[string]error{
			corrupt.String(): fmt.Errorf("registry repository: scan: decrypt auth: %w: illegal base64", commonerrors.ErrCorruptData),
		}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
	)

	snapshot, err := compiler.Compile(context.Background())
	if err != nil {
		t.Fatalf("compile should skip corrupt gateway, got: %v", err)
	}
	data := snapshot.Data()
	if len(data.Gateways) != 1 || data.Gateways[0].ID != healthy {
		t.Fatalf("expected only the healthy gateway, got %+v", data.Gateways)
	}
	if len(data.Consumers) != 1 || data.Consumers[0].GatewayID != healthy {
		t.Fatalf("expected only the healthy gateway consumers, got %+v", data.Consumers)
	}
}

func TestCompilerFailsWhenAllGatewaysCorrupt(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")

	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{errByGateway: map[string]error{
			gwA.String(): fmt.Errorf("decrypt auth: %w: illegal base64", commonerrors.ErrCorruptData),
			gwB.String(): fmt.Errorf("decrypt auth: %w: illegal base64", commonerrors.ErrCorruptData),
		}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
	)

	if _, err := compiler.Compile(context.Background()); err == nil {
		t.Fatalf("expected compile to fail when every gateway is corrupt")
	} else if !errors.Is(err, commonerrors.ErrCorruptData) {
		t.Fatalf("expected ErrCorruptData, got: %v", err)
	}
}

func TestCompilerPropagatesNonCorruptErrors(t *testing.T) {
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	boom := errors.New("db connection refused")

	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{errByGateway: map[string]error{gwA.String(): boom}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
	)

	if _, err := compiler.Compile(context.Background()); err == nil {
		t.Fatalf("expected compile to propagate non-corrupt errors")
	} else if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped boom error, got: %v", err)
	}
}

// skippingPolicies mimics the policy repository after RUN-1663: a page is built
// from the rows the query matched, unreadable rows are dropped from it, and the
// total still counts them. A full page therefore comes back one row short.
type skippingPolicies struct {
	rows       []*policydomain.Policy
	unreadable map[int]bool
	// cancelFirstCall makes the first List call block until its context is done
	// and fail with ctx.Err(), so the bulk policies scan is always the one an
	// errgroup cancellation kills.
	cancelFirstCall *atomic.Bool
}

func (f skippingPolicies) ListByGateway(context.Context, ids.GatewayID) ([]*policydomain.Policy, error) {
	return nil, nil
}

func (f skippingPolicies) List(ctx context.Context, filter policydomain.ListFilter) ([]*policydomain.Policy, int, error) {
	if f.cancelFirstCall != nil && f.cancelFirstCall.CompareAndSwap(false, true) {
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	number, size := filter.Page.Number, filter.Page.Size
	start := (number - 1) * size
	if start >= len(f.rows) {
		return nil, len(f.rows), nil
	}
	end := min(start+size, len(f.rows))
	out := make([]*policydomain.Policy, 0, end-start)
	for i := start; i < end; i++ {
		if f.unreadable[i] {
			continue
		}
		out = append(out, f.rows[i])
	}
	return out, len(f.rows), nil
}

func TestCompilerKeepsPagingWhenARepositorySkipsUnreadableRows(t *testing.T) {
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	rows := make([]*policydomain.Policy, 0, 501)
	for range 501 {
		rows = append(rows, &policydomain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gw})
	}
	// Row 3 sits on the first, full page: the page comes back with 499 rows, and
	// the 501st row lives on the second page.
	policies := skippingPolicies{rows: rows, unreadable: map[int]bool{3: true}}

	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gw}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		policies,
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
	)

	snapshot, err := compiler.Compile(context.Background())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := len(snapshot.Data().Policies); got != 500 {
		t.Fatalf("expected the 500 readable policies, got %d (a short page ended the walk early)", got)
	}
}

func compileWithSkippedPolicies(t *testing.T, total int, unreadable ...int) (int, error) {
	t.Helper()
	return compileWithSkippedPoliciesAndRegistries(t, fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}}, false, total, unreadable...)
}

func compileWithSkippedPoliciesAndRegistries(t *testing.T, registries appsnapshot.RegistryReader, cancelFirstPoliciesCall bool, total int, unreadable ...int) (int, error) {
	t.Helper()
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	rows := make([]*policydomain.Policy, 0, total)
	for range total {
		rows = append(rows, &policydomain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gw})
	}
	skip := map[int]bool{}
	for _, i := range unreadable {
		skip[i] = true
	}
	policies := skippingPolicies{rows: rows, unreadable: skip}
	if cancelFirstPoliciesCall {
		policies.cancelFirstCall = &atomic.Bool{}
	}
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gw}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		registries,
		policies,
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
	)
	snapshot, err := compiler.Compile(context.Background())
	if err != nil {
		return 0, err
	}
	return len(snapshot.Data().Policies), nil
}

// A few corrupt rows are skipped so the rest keep enforcing; a mass failure is a
// systemic bug and must fail the compile so running pods keep their last known
// good snapshot instead of swapping in one without the guardrails.
func TestCompilerMassUnreadablePoliciesFailTheCompile(t *testing.T) {
	tests := []struct {
		name       string
		total      int
		unreadable []int
		wantErr    bool
		wantCount  int
	}{
		{name: "1 of 1 unreadable fails", total: 1, unreadable: []int{0}, wantErr: true},
		{name: "1 of 10 unreadable keeps the other 9", total: 10, unreadable: []int{4}, wantCount: 9},
		{name: "2 of 10 unreadable fails", total: 10, unreadable: []int{1, 2}, wantErr: true},
		{name: "2 of 19 unreadable fails", total: 19, unreadable: []int{1, 2}, wantErr: true},
		{name: "2 of 21 unreadable keeps the other 19", total: 21, unreadable: []int{1, 2}, wantCount: 19},
		{name: "3 of 21 unreadable fails", total: 21, unreadable: []int{1, 2, 3}, wantErr: true},
		{name: "1 of 5 unreadable keeps the other 4", total: 5, unreadable: []int{2}, wantCount: 4},
		{name: "2 of 5 unreadable fails", total: 5, unreadable: []int{1, 2}, wantErr: true},
		{name: "5 of 5 unreadable fails", total: 5, unreadable: []int{0, 1, 2, 3, 4}, wantErr: true},
		{name: "1 of 20 unreadable keeps the other 19", total: 20, unreadable: []int{4}, wantCount: 19},
		{name: "exactly 10 percent is still skipped", total: 20, unreadable: []int{4, 9}, wantCount: 18},
		{name: "more than 10 percent fails", total: 20, unreadable: []int{1, 2, 3}, wantErr: true},
		{name: "every row unreadable fails", total: 3, unreadable: []int{0, 1, 2}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compileWithSkippedPolicies(t, tt.total, tt.unreadable...)
			if tt.wantErr {
				if !errors.Is(err, commonerrors.ErrCorruptData) {
					t.Fatalf("expected an error wrapping ErrCorruptData, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got != tt.wantCount {
				t.Fatalf("expected %d policies, got %d", tt.wantCount, got)
			}
		})
	}
}

// A corrupt registries row makes the bulk collect fail with ErrCorruptData and
// cancels the other scans, so the compile falls back to per-gateway collection.
// The mass-skip breaker must still hold on that path. The first policies List is
// blocked until the registries error cancels it, so the bulk policies scan never
// reaches its own check and only the fallback's re-check can trip.
func TestCompilerMassUnreadablePoliciesFailEvenWhenRegistriesAreCorrupt(t *testing.T) {
	// Only the bulk scan trips on the corrupt row; the compiled gateway's own
	// registries read fine, so the fallback would otherwise succeed.
	registries := fakeRegistries{errByGateway: map[string]error{
		"99999999-9999-9999-9999-999999999999": fmt.Errorf("scan auth: %w", commonerrors.ErrCorruptData),
	}}
	_, err := compileWithSkippedPoliciesAndRegistries(t, registries, true, 20, 1, 2, 3)
	if !errors.Is(err, appsnapshot.ErrUnreadablePolicies) {
		t.Fatalf("expected ErrUnreadablePolicies, got %v", err)
	}
}

func TestCompilerShipsOwnedKeys(t *testing.T) {
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	corrupt := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	application := &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: authdomain.TypeAPIKey, Enabled: true, KeyHash: "application-hash"}
	owned := &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: authdomain.TypeAPIKey, Enabled: true, KeyHash: "owned-hash", OwnerID: "alice"}
	perGateway := fakeRegistries{errByGateway: map[string]error{corrupt.String(): fmt.Errorf("decrypt auth: %w", commonerrors.ErrCorruptData)}}

	for name, registries := range map[string]fakeRegistries{"bulk": {}, "per gateway": perGateway} {
		t.Run(name, func(t *testing.T) {
			snapshot, err := appsnapshot.NewCompiler(
				fakeGateways{items: []*gatewaydomain.Gateway{{ID: gw}, {ID: corrupt}}},
				fakeConsumers{},
				registries,
				fakePolicies{},
				fakeAuths{byGateway: map[string][]*authdomain.Auth{gw.String(): {application, owned}}},
				fakeCatalog{},
				nil,
			).Compile(context.Background())
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			found, ok := snapshot.AuthByAPIKeyHash("owned-hash")
			if len(snapshot.Data().Auths) != 2 || !ok || found.ID != owned.ID || found.OwnerID != "alice" {
				t.Fatalf("auths = %+v, owned lookup = %+v, %v", snapshot.Data().Auths, found, ok)
			}
		})
	}
}
