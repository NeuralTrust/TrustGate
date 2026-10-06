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
	"sync"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePinnedTools struct {
	mu         sync.Mutex
	byRegistry map[ids.RegistryID][]registrydomain.PinnedTool
	err        error
	errFor     map[ids.RegistryID]error
	calls      []ids.RegistryID
}

func (f *fakePinnedTools) ListByRegistry(_ context.Context, _ ids.GatewayID, registryID ids.RegistryID) ([]registrydomain.PinnedTool, error) {
	f.mu.Lock()
	f.calls = append(f.calls, registryID)
	f.mu.Unlock()
	if err := f.errFor[registryID]; err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.byRegistry[registryID], nil
}

func pinnedRegistry(t *testing.T, gw ids.GatewayID, policy registrydomain.ToolPolicy) *registrydomain.Registry {
	t.Helper()
	id, err := ids.NewV7[ids.RegistryKind]()
	require.NoError(t, err)
	return &registrydomain.Registry{ID: id, GatewayID: gw, Type: registrydomain.TypeMCP, ToolPolicy: policy}
}

func compileWithPinned(t *testing.T, regs fakeRegistries, gw ids.GatewayID, pinned appsnapshot.PinnedToolReader) (map[ids.RegistryID]*registrydomain.Registry, error) {
	t.Helper()
	opts := []appsnapshot.CompilerOption{}
	if pinned != nil {
		opts = append(opts, appsnapshot.WithPinnedTools(pinned))
	}
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gw}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		regs,
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
		opts...,
	)
	snap, err := compiler.Compile(context.Background())
	if err != nil {
		return nil, err
	}
	out := map[ids.RegistryID]*registrydomain.Registry{}
	for _, r := range snap.RegistriesByGateway(gw) {
		out[r.ID] = r
	}
	return out, nil
}

func TestCompilerStampsPinnedRegistriesWithDecidedTools(t *testing.T) {
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	pinned := pinnedRegistry(t, gw, registrydomain.ToolPolicyPinned)
	auto := pinnedRegistry(t, gw, registrydomain.ToolPolicyAuto)
	reader := &fakePinnedTools{byRegistry: map[ids.RegistryID][]registrydomain.PinnedTool{
		pinned.ID: {
			{Name: "zeta", Fingerprint: "f2", Status: registrydomain.ToolStatusRejected},
			{Name: "alpha", Fingerprint: "f1", Status: registrydomain.ToolStatusApproved},
			{Name: "beta", Fingerprint: "f3", Status: registrydomain.ToolStatusPending},
		},
		auto.ID: {{Name: "ignored", Fingerprint: "f9", Status: registrydomain.ToolStatusApproved}},
	}}
	regs := fakeRegistries{byGateway: map[string][]*registrydomain.Registry{gw.String(): {pinned, auto}}}

	got, err := compileWithPinned(t, regs, gw, reader)
	require.NoError(t, err)

	assert.Equal(t, []registrydomain.ToolDecision{
		{Name: "alpha", Fingerprint: "f1", Status: registrydomain.ToolStatusApproved},
		{Name: "zeta", Fingerprint: "f2", Status: registrydomain.ToolStatusRejected},
	}, got[pinned.ID].PinnedTools, "pending is not carried and the set is sorted")
	assert.Empty(t, got[auto.ID].PinnedTools)
	assert.Equal(t, []ids.RegistryID{pinned.ID}, reader.calls, "auto registries are never read")
}

func TestCompilerStampsPinnedToolsOnPerGatewayFallback(t *testing.T) {
	good := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	corrupt := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	pinned := pinnedRegistry(t, good, registrydomain.ToolPolicyPinned)
	reader := &fakePinnedTools{byRegistry: map[ids.RegistryID][]registrydomain.PinnedTool{
		pinned.ID: {{Name: "alpha", Fingerprint: "f1", Status: registrydomain.ToolStatusApproved}},
	}}
	regs := fakeRegistries{
		byGateway:    map[string][]*registrydomain.Registry{good.String(): {pinned}},
		errByGateway: map[string]error{corrupt.String(): fmt.Errorf("decrypt auth: %w", commonerrors.ErrCorruptData)},
	}
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: good}, {ID: corrupt}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		regs,
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
		appsnapshot.WithPinnedTools(reader),
	)
	snap, err := compiler.Compile(context.Background())
	require.NoError(t, err)
	got := snap.RegistriesByGateway(good)
	require.Len(t, got, 1)
	assert.Len(t, got[0].PinnedTools, 1)
}

func TestCompilerFailsWhenPinnedToolsCannotBeRead(t *testing.T) {
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	pinned := pinnedRegistry(t, gw, registrydomain.ToolPolicyPinned)
	regs := fakeRegistries{byGateway: map[string][]*registrydomain.Registry{gw.String(): {pinned}}}

	_, err := compileWithPinned(t, regs, gw, &fakePinnedTools{err: errors.New("db down")})
	require.Error(t, err, "publishing without the set would hide approved tools; keep the last good snapshot")
}

func TestCompilerWithoutPinnedReaderLeavesRegistriesUntouched(t *testing.T) {
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	pinned := pinnedRegistry(t, gw, registrydomain.ToolPolicyPinned)
	regs := fakeRegistries{byGateway: map[string][]*registrydomain.Registry{gw.String(): {pinned}}}

	got, err := compileWithPinned(t, regs, gw, nil)
	require.NoError(t, err)
	assert.Empty(t, got[pinned.ID].PinnedTools)
}

func TestCompilerSkipsAGatewayWhoseDecisionsAreCorrupt(t *testing.T) {
	good := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	bad := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	okReg := pinnedRegistry(t, good, registrydomain.ToolPolicyPinned)
	badReg := pinnedRegistry(t, bad, registrydomain.ToolPolicyPinned)
	reader := &fakePinnedTools{
		byRegistry: map[ids.RegistryID][]registrydomain.PinnedTool{
			okReg.ID: {{Name: "alpha", Fingerprint: "f1", Status: registrydomain.ToolStatusApproved}},
		},
		errFor: map[ids.RegistryID]error{badReg.ID: fmt.Errorf("scan status: %w", commonerrors.ErrCorruptData)},
	}
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: good}, {ID: bad}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{good.String(): {okReg}, bad.String(): {badReg}}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
		appsnapshot.WithPinnedTools(reader),
	)

	snap, err := compiler.Compile(context.Background())
	require.NoError(t, err, "one tenant's corrupt row must not freeze everyone's config")
	assert.Len(t, snap.RegistriesByGateway(good), 1)
	assert.Empty(t, snap.RegistriesByGateway(bad), "the corrupt gateway is skipped, like other corrupt data")
}

func TestCompilerFailsOnATransientPinnedReadEvenWithOtherGateways(t *testing.T) {
	good := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	other := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	okReg := pinnedRegistry(t, good, registrydomain.ToolPolicyPinned)
	flaky := pinnedRegistry(t, other, registrydomain.ToolPolicyPinned)
	reader := &fakePinnedTools{errFor: map[ids.RegistryID]error{flaky.ID: errors.New("connection reset")}}
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: good}, {ID: other}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{good.String(): {okReg}, other.String(): {flaky}}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
		appsnapshot.WithPinnedTools(reader),
	)

	_, err := compiler.Compile(context.Background())
	require.Error(t, err, "a transient error must keep the last good snapshot, not publish a partial one")
}
