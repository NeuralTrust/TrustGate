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
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
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

type fakeRegistries struct {
	byGateway    map[string][]*registrydomain.Registry
	errByGateway map[string]error
	err          error
}

func (f fakeRegistries) List(_ context.Context, filter registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	if f.err != nil {
		return nil, 0, f.err
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

type fakeAuths struct {
	byGateway map[string][]*authdomain.Auth
	err       error
}

func (f fakeAuths) List(_ context.Context, filter authdomain.ListFilter) ([]*authdomain.Auth, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	if filter.Page > 1 {
		return nil, 0, nil
	}
	items := f.byGateway[filter.GatewayID.String()]
	return items, len(items), nil
}

type fakeRoles struct {
	byGateway map[string][]*roledomain.Role
	err       error
}

func (f fakeRoles) ListByGateway(_ context.Context, gatewayID ids.GatewayID) ([]*roledomain.Role, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byGateway[gatewayID.String()], nil
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
		fakeRoles{byGateway: map[string][]*roledomain.Role{}},
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
		fakeRoles{byGateway: map[string][]*roledomain.Role{}},
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
		fakeRoles{err: commonerrors.ErrNotFound},
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
		fakeRoles{},
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
		fakeRoles{byGateway: map[string][]*roledomain.Role{}},
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
		fakeRoles{byGateway: map[string][]*roledomain.Role{}},
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
		fakeRoles{byGateway: map[string][]*roledomain.Role{}},
		fakeCatalog{},
		nil,
	)

	if _, err := compiler.Compile(context.Background()); err == nil {
		t.Fatalf("expected compile to propagate non-corrupt errors")
	} else if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped boom error, got: %v", err)
	}
}
