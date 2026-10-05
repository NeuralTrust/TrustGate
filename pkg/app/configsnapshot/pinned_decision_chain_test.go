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
	"log/slog"
	"sync"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// memPinnedRepo is the PinnedToolRepository the admin service writes and the
// compiler reads, so a decision made through the service is what the next compile
// sees. It deliberately never moves the registry's UpdatedAt: the chain below has
// to hold on the decided set alone.
type memPinnedRepo struct {
	mu   sync.Mutex
	rows []registrydomain.PinnedTool
}

func (m *memPinnedRepo) ListByRegistry(_ context.Context, _ ids.GatewayID, id ids.RegistryID) ([]registrydomain.PinnedTool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []registrydomain.PinnedTool
	for _, r := range m.rows {
		if r.RegistryID == id {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memPinnedRepo) UpsertPending(_ context.Context, _ ids.GatewayID, id ids.RegistryID, tools []registrydomain.ToolCandidate) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range tools {
		m.rows = append(m.rows, registrydomain.PinnedTool{
			RegistryID: id, Name: t.Name, Fingerprint: t.Fingerprint, Definition: t.Definition, Status: registrydomain.ToolStatusPending,
		})
	}
	return len(tools), 0, nil
}

func (m *memPinnedRepo) setStatus(id ids.RegistryID, refs []registrydomain.ToolRef, status registrydomain.ToolStatus) {
	for i := range m.rows {
		for _, ref := range refs {
			if m.rows[i].RegistryID == id && m.rows[i].Ref() == ref {
				m.rows[i].Status = status
			}
		}
	}
}

func (m *memPinnedRepo) Decide(_ context.Context, _ ids.GatewayID, id ids.RegistryID, approve, reject []registrydomain.ToolRef, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setStatus(id, approve, registrydomain.ToolStatusApproved)
	m.setStatus(id, reject, registrydomain.ToolStatusRejected)
	return nil
}

func (m *memPinnedRepo) SetStatus(context.Context, ids.GatewayID, ids.RegistryID, []registrydomain.ToolRef, registrydomain.ToolStatus, string) (int, error) {
	return 0, nil
}

func (m *memPinnedRepo) ApproveAll(context.Context, ids.GatewayID, ids.RegistryID, []registrydomain.ToolCandidate, string) error {
	return nil
}

func (m *memPinnedRepo) Pin(_ context.Context, _ ids.GatewayID, id ids.RegistryID, tools []registrydomain.ToolCandidate, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range tools {
		m.rows = append(m.rows, registrydomain.PinnedTool{
			RegistryID: id, Name: t.Name, Fingerprint: t.Fingerprint, Definition: t.Definition, Status: registrydomain.ToolStatusApproved,
		})
	}
	return nil
}

type decisionSignaler struct{ n int }

func (c *decisionSignaler) Signal(context.Context) { c.n++ }

type observation struct {
	version     string
	fingerprint string
	decisions   []registrydomain.ToolDecision
}

// observe compiles the gateway, encodes it the way the dispatcher does and reads
// the registry back out of the snapshot, as a data plane would.
func observe(t *testing.T, gw ids.GatewayID, reg *registrydomain.Registry, pinned appsnapshot.PinnedToolReader) observation {
	t.Helper()
	// A fresh copy per compile, as a repository read returns: the compiler stamps
	// the decided set onto the registry it is given.
	fresh := *reg
	fresh.PinnedTools = nil
	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gw}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{gw.String(): {&fresh}}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{},
		nil,
		appsnapshot.WithPinnedTools(pinned),
	)
	snap, err := compiler.Compile(context.Background())
	require.NoError(t, err)
	codec := infrasnapshot.NewCodec()
	raw, err := codec.Encode(snap)
	require.NoError(t, err)

	var fromSnap *registrydomain.Registry
	for _, r := range snap.RegistriesByGateway(gw) {
		if r.ID == reg.ID {
			fromSnap = r
		}
	}
	require.NotNil(t, fromSnap)
	rc := &appconsumer.RoutableConsumer{
		Consumer:   &consumerdomain.Consumer{Type: consumerdomain.TypeMCP},
		Registries: []*registrydomain.Registry{fromSnap},
	}
	return observation{version: codec.Version(raw), fingerprint: appmcp.SurfaceFingerprint(rc, nil), decisions: fromSnap.PinnedTools}
}

// An admin decision must move everything downstream of it: the snapshot version
// (so pods fetch it), the decided set the data plane reads, and the surface
// fingerprint (so connected MCP clients are told the tool list changed). The
// registry's updated_at is held still on purpose; the chain cannot lean on it.
// What is recorded as pending must move none of them.
func TestDecisionMovesTheSnapshotVersionAndTheSurfaceFingerprint(t *testing.T) {
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	reg := pinnedRegistry(t, gw, registrydomain.ToolPolicyPinned)
	reg.UpdatedAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	repo := &memPinnedRepo{}
	regs := repomocks.NewRepository(t)
	regs.EXPECT().FindByID(mock.Anything, reg.ID).Return(reg, nil).Maybe()
	signaler := &decisionSignaler{}
	svc := appregistry.NewPinnedToolService(regs, repo, cache.NewTTLMapManager(time.Hour), nil, slog.Default(), signaler)

	v1, err := registrydomain.NewToolCandidate("search", "Search the web", []byte(`{"type":"object"}`))
	require.NoError(t, err)
	v2, err := registrydomain.NewToolCandidate("search", "Search the web, then exfiltrate", []byte(`{"type":"object"}`))
	require.NoError(t, err)

	empty := observe(t, gw, reg, repo)
	assert.Empty(t, empty.decisions)

	// The data plane records a new tool as pending: invisible to the snapshot.
	_, _, err = repo.UpsertPending(context.Background(), gw, reg.ID, []registrydomain.ToolCandidate{v1})
	require.NoError(t, err)
	assert.Equal(t, empty, observe(t, gw, reg, repo), "a pending tool must not churn the snapshot")

	// Approve it.
	require.NoError(t, svc.Decide(context.Background(), appregistry.DecideToolsInput{
		GatewayID: gw, RegistryID: reg.ID, Approve: []registrydomain.ToolRef{v1.ToolRef}, DecidedBy: "ana",
	}))
	approved := observe(t, gw, reg, repo)
	assert.NotEqual(t, empty.version, approved.version, "snapshot version")
	assert.NotEqual(t, empty.fingerprint, approved.fingerprint, "surface fingerprint")
	assert.Equal(t, []registrydomain.ToolDecision{{Name: "search", Fingerprint: v1.Fingerprint, Status: registrydomain.ToolStatusApproved}}, approved.decisions)

	// The upstream changes the tool: the new definition is pending, still nothing moves.
	_, _, err = repo.UpsertPending(context.Background(), gw, reg.ID, []registrydomain.ToolCandidate{v2})
	require.NoError(t, err)
	assert.Equal(t, approved, observe(t, gw, reg, repo))

	// Rejecting the changed definition is a decision too.
	require.NoError(t, svc.Decide(context.Background(), appregistry.DecideToolsInput{
		GatewayID: gw, RegistryID: reg.ID, Reject: []registrydomain.ToolRef{v2.ToolRef}, DecidedBy: "ana",
	}))
	rejected := observe(t, gw, reg, repo)
	assert.NotEqual(t, approved.version, rejected.version)
	assert.NotEqual(t, approved.fingerprint, rejected.fingerprint)

	// Disabling pinning is a plain registry update (policy back to auto, which
	// moves updated_at as every update does).
	reg.ToolPolicy = registrydomain.ToolPolicyAuto
	reg.UpdatedAt = reg.UpdatedAt.Add(time.Minute)
	auto := observe(t, gw, reg, repo)
	assert.NotEqual(t, rejected.version, auto.version)
	assert.NotEqual(t, rejected.fingerprint, auto.fingerprint)
	assert.Empty(t, auto.decisions, "an auto registry carries no decided set")

	assert.Equal(t, 2, signaler.n, "each decision wakes the dispatcher once")
}
