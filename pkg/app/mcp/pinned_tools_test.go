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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pinnedURL = "https://pinned.example.com/mcp"

type recordedBatch struct {
	gatewayID  ids.GatewayID
	registryID ids.RegistryID
	tools      []registrydomain.ToolCandidate
}

type fakeRecorder struct {
	mu      sync.Mutex
	batches []recordedBatch
	err     error
}

func (f *fakeRecorder) Record(_ context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, tools []registrydomain.ToolCandidate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, recordedBatch{gatewayID, registryID, tools})
	return f.err
}

func (f *fakeRecorder) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.batches)
}

func (f *fakeRecorder) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, b := range f.batches {
		for _, c := range b.tools {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

func defTool(t *testing.T, name, description string) Tool {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"name":        name,
		"description": description,
		"inputSchema": map[string]any{"type": "object"},
	})
	require.NoError(t, err)
	var tool Tool
	require.NoError(t, json.Unmarshal(raw, &tool))
	return tool
}

func refOf(t *testing.T, tool Tool) registrydomain.ToolRef {
	t.Helper()
	cand, err := registrydomain.NewToolCandidate(tool.Name, tool.Description(), tool.InputSchema())
	require.NoError(t, err)
	return cand.ToolRef
}

func decision(t *testing.T, tool Tool, status registrydomain.ToolStatus) registrydomain.ToolDecision {
	t.Helper()
	ref := refOf(t, tool)
	return registrydomain.ToolDecision{Name: ref.Name, Fingerprint: ref.Fingerprint, Status: status}
}

func pinnedReg(t *testing.T, decided ...registrydomain.ToolDecision) *registrydomain.Registry {
	t.Helper()
	reg := mcpRegistry(t, "pinned", pinnedURL)
	reg.ToolPolicy = registrydomain.ToolPolicyPinned
	reg.PinnedTools = decided
	return reg
}

type pinnedHarness struct {
	composer Composer
	upstream *fakeUpstream
	dialer   *countingDialer
	recorder *fakeRecorder
}

func newPinnedHarness(t *testing.T, upstreamTools []Tool, recorder *fakeRecorder) *pinnedHarness {
	t.Helper()
	up := &fakeUpstream{tools: upstreamTools, result: json.RawMessage(`{"content":[]}`)}
	dialer := newCountingDialer(func(string) (Upstream, error) { return up, nil })
	opts := []ComposerOption{}
	if recorder != nil {
		opts = append(opts, WithPendingToolRecorder(recorder))
	}
	return &pinnedHarness{
		composer: NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler), opts...),
		upstream: up,
		dialer:   dialer,
		recorder: recorder,
	}
}

func (h *pinnedHarness) list(t *testing.T, rc *appconsumer.RoutableConsumer) []string {
	t.Helper()
	got, err := h.composer.ListTools(context.Background(), rc)
	require.NoError(t, err)
	prefix := namedFor(rc.Registries[0], "")
	names := make([]string, 0, len(got))
	for _, n := range toolNames(got) {
		names = append(names, strings.TrimPrefix(n, prefix))
	}
	sort.Strings(names)
	return names
}

func TestPinned_NewAndModifiedToolsAreHiddenAndRecorded(t *testing.T) {
	t.Parallel()
	keep := defTool(t, "keep", "stays the same")
	search := defTool(t, "search", "v1")
	reg := pinnedReg(t, decision(t, keep, registrydomain.ToolStatusApproved), decision(t, search, registrydomain.ToolStatusApproved))
	rec := &fakeRecorder{}
	h := newPinnedHarness(t, []Tool{keep, search}, rec)
	rc := routable(mcpClient(), reg)

	assert.Equal(t, []string{"keep", "search"}, h.list(t, rc))
	assert.Zero(t, rec.calls(), "everything is approved, nothing to record")

	searchV2 := defTool(t, "search", "v2: now exfiltrates")
	h.upstream.tools = []Tool{keep, searchV2, defTool(t, "new", "added later")}
	reg.UpdatedAt = reg.UpdatedAt.Add(time.Second) // busts the discovery cache

	assert.Equal(t, []string{"keep"}, h.list(t, rc))
	assert.Equal(t, 1, rec.calls(), "one Record per discovery")
	assert.Equal(t, []string{"new", "search"}, rec.names())
	assert.Equal(t, reg.ID, rec.batches[0].registryID)
	assert.Equal(t, reg.GatewayID, rec.batches[0].gatewayID)

	for _, hidden := range []string{"search", "new"} {
		target, err := h.composer.Resolve(context.Background(), rc, namedFor(reg, hidden))
		assert.ErrorIs(t, err, ErrToolNotFound, "tools/call on %q must not resolve", hidden)
		assert.Nil(t, target)
	}
	assert.Empty(t, h.upstream.lastCall)
}

func TestPinned_ToolkitNeverWidensTheApprovedSet(t *testing.T) {
	t.Parallel()
	ok := defTool(t, "ok", "approved")
	bad := defTool(t, "bad", "not approved")
	reg := pinnedReg(t, decision(t, ok, registrydomain.ToolStatusApproved))

	cases := map[string]*consumerdomain.Consumer{
		"nil toolkit": mcpClient(),
		"wildcard": {Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: reg.ID, Tool: consumerdomain.ToolWildcard},
		}}},
		"names the unapproved tool": {Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
			{RegistryID: reg.ID, Tool: "ok"}, {RegistryID: reg.ID, Tool: "bad"},
		}}},
	}
	for name, consumer := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newPinnedHarness(t, []Tool{ok, bad}, &fakeRecorder{})
			rc := routable(consumer, reg)
			assert.Equal(t, []string{"ok"}, h.list(t, rc))
			_, err := h.composer.Resolve(context.Background(), rc, namedFor(reg, "bad"))
			assert.Error(t, err)
		})
	}
}

func TestPinned_StatusDecidesVisibility(t *testing.T) {
	t.Parallel()
	approved := defTool(t, "approved", "a")
	rejected := defTool(t, "rejected", "r")
	pending := defTool(t, "pending", "p") // recorded earlier; the snapshot does not carry pending rows
	reg := pinnedReg(t,
		decision(t, approved, registrydomain.ToolStatusApproved),
		decision(t, rejected, registrydomain.ToolStatusRejected),
	)
	rec := &fakeRecorder{}
	h := newPinnedHarness(t, []Tool{approved, rejected, pending}, rec)

	assert.Equal(t, []string{"approved"}, h.list(t, routable(mcpClient(), reg)))
	assert.Equal(t, []string{"pending"}, rec.names(), "a rejected tool is decided: it is never recorded again")
}

func TestPinned_AutoRegistryIsUntouched(t *testing.T) {
	t.Parallel()
	a, b := defTool(t, "a", "x"), defTool(t, "b", "y")
	reg := mcpRegistry(t, "auto", pinnedURL)
	require.Equal(t, registrydomain.ToolPolicyAuto, reg.ToolPolicy)
	rec := &fakeRecorder{}
	h := newPinnedHarness(t, []Tool{a, b}, rec)

	assert.Equal(t, []string{"a", "b"}, h.list(t, routable(mcpClient(), reg)))
	assert.Zero(t, rec.calls())
}

func TestPinned_RecorderFailureStillReturnsTheFilteredList(t *testing.T) {
	t.Parallel()
	ok := defTool(t, "ok", "approved")
	reg := pinnedReg(t, decision(t, ok, registrydomain.ToolStatusApproved))
	rec := &fakeRecorder{err: errors.New("control plane unreachable")}
	h := newPinnedHarness(t, []Tool{ok, defTool(t, "new", "n")}, rec)
	rc := routable(mcpClient(), reg)

	assert.Equal(t, []string{"ok"}, h.list(t, rc))
	assert.Equal(t, 1, rec.calls())

	// The filtered list is cached as usual: no second dial and no second Record.
	assert.Equal(t, []string{"ok"}, h.list(t, rc))
	assert.Equal(t, 1, h.dialer.count(pinnedURL))
	assert.Equal(t, 1, rec.calls())
}

func TestPinned_WithoutRecorderUnknownToolsAreHidden(t *testing.T) {
	t.Parallel()
	ok := defTool(t, "ok", "approved")
	reg := pinnedReg(t, decision(t, ok, registrydomain.ToolStatusApproved))
	h := newPinnedHarness(t, []Tool{ok, defTool(t, "new", "n")}, nil)

	assert.Equal(t, []string{"ok"}, h.list(t, routable(mcpClient(), reg)))
}

func TestPinned_RegistryWithoutASetExposesNothing(t *testing.T) {
	t.Parallel()
	// An old control plane publishes a pinned registry with no set.
	reg := pinnedReg(t)
	rec := &fakeRecorder{}
	h := newPinnedHarness(t, []Tool{defTool(t, "a", "x")}, rec)

	assert.Empty(t, h.list(t, routable(mcpClient(), reg)))
	assert.Equal(t, []string{"a"}, rec.names())
}

func TestPinned_ToolWithNULIsHiddenAndNotRecorded(t *testing.T) {
	t.Parallel()
	ok := defTool(t, "ok", "approved")
	nul := defTool(t, "nul", "bad\u0000description")
	reg := pinnedReg(t, decision(t, ok, registrydomain.ToolStatusApproved))
	rec := &fakeRecorder{}
	h := newPinnedHarness(t, []Tool{ok, nul, defTool(t, "new", "n")}, rec)

	assert.Equal(t, []string{"ok"}, h.list(t, routable(mcpClient(), reg)))
	assert.Equal(t, []string{"new"}, rec.names(), "the NUL tool must not poison the batch")
}

func TestPinned_ADecisionChangesTheCachedSurface(t *testing.T) {
	t.Parallel()
	a, b := defTool(t, "a", "x"), defTool(t, "b", "y")
	reg := pinnedReg(t, decision(t, a, registrydomain.ToolStatusApproved))
	h := newPinnedHarness(t, []Tool{a, b}, &fakeRecorder{})

	assert.Equal(t, []string{"a"}, h.list(t, routable(mcpClient(), reg)))

	// Same registry id and updated_at, new decided set: the key must differ.
	approved := *reg
	approved.PinnedTools = append([]registrydomain.ToolDecision{}, reg.PinnedTools...)
	approved.PinnedTools = append(approved.PinnedTools, decision(t, b, registrydomain.ToolStatusApproved))
	assert.Equal(t, []string{"a", "b"}, h.list(t, routable(mcpClient(), &approved)))
}
