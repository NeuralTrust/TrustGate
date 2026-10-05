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
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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
	// block, when set, holds every Record until it is closed or ctx ends.
	block chan struct{}
	// ctxErr keeps what the context looked like when a blocked Record returned.
	ctxErr error
}

func (f *fakeRecorder) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeRecorder) Record(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID, tools []registrydomain.ToolCandidate) error {
	f.mu.Lock()
	f.batches = append(f.batches, recordedBatch{gatewayID, registryID, tools})
	err, block := f.err, f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			f.mu.Lock()
			f.ctxErr = ctx.Err()
			f.mu.Unlock()
		}
	}
	return err
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
	async    *AsyncPendingRecorder
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
	var async *AsyncPendingRecorder
	if recorder != nil {
		async = NewAsyncPendingRecorder(recorder, slog.New(slog.DiscardHandler))
		t.Cleanup(async.Close)
		opts = append(opts, WithPendingToolSink(async))
	}
	return &pinnedHarness{
		async:    async,
		composer: NewComposer(dialer, nil, newMapCache(), slog.New(slog.DiscardHandler), opts...),
		upstream: up,
		dialer:   dialer,
		recorder: recorder,
	}
}

// settle waits until the async recorder has nothing queued or in flight, so a
// test can assert on what it recorded, or did not.
func (h *pinnedHarness) settle(t *testing.T) {
	t.Helper()
	if h.async == nil {
		return
	}
	require.Eventually(t, h.async.idle, 2*time.Second, time.Millisecond)
}

func (h *pinnedHarness) list(t *testing.T, rc *appconsumer.RoutableConsumer) []string {
	t.Helper()
	got, err := h.composer.ListTools(context.Background(), rc)
	require.NoError(t, err)
	h.settle(t)
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
	rec := &fakeRecorder{}
	rec.setErr(errors.New("control plane unreachable"))
	h := newPinnedHarness(t, []Tool{ok, defTool(t, "new", "n")}, rec)
	rc := routable(mcpClient(), reg)

	assert.Equal(t, []string{"ok"}, h.list(t, rc))
	assert.Equal(t, 1, rec.calls())

	// The filtered list is cached as usual: no second dial and no second Record.
	assert.Equal(t, []string{"ok"}, h.list(t, rc))
	assert.Equal(t, 1, h.dialer.count(pinnedURL))
	assert.Equal(t, 1, rec.calls())

	// The failure forgot the keys: the next discovery (cache busted) retries.
	rec.setErr(nil)
	reg.UpdatedAt = reg.UpdatedAt.Add(time.Second)
	assert.Equal(t, []string{"ok"}, h.list(t, rc))
	assert.Equal(t, 2, rec.calls())
	assert.Equal(t, []string{"new", "new"}, rec.names())

	// And once it succeeded the keys are remembered: no third Record.
	reg.UpdatedAt = reg.UpdatedAt.Add(time.Second)
	assert.Equal(t, []string{"ok"}, h.list(t, rc))
	assert.Equal(t, 2, rec.calls())
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

func TestPinned_WarmCacheFlipBetweenAutoAndPinned(t *testing.T) {
	t.Parallel()
	a, b := defTool(t, "a", "x"), defTool(t, "b", "y")
	h := newPinnedHarness(t, []Tool{a, b}, &fakeRecorder{})
	reg := mcpRegistry(t, "flip", pinnedURL)
	rc := routable(mcpClient(), reg)

	assert.Equal(t, []string{"a", "b"}, h.list(t, rc), "auto: everything")

	// Same registry id and updated_at, only the policy moves.
	reg.ToolPolicy = registrydomain.ToolPolicyPinned
	reg.PinnedTools = []registrydomain.ToolDecision{decision(t, a, registrydomain.ToolStatusApproved)}
	assert.Equal(t, []string{"a"}, h.list(t, rc), "pinned must not be served the warm auto list")

	reg.ToolPolicy = registrydomain.ToolPolicyAuto
	reg.PinnedTools = nil
	assert.Equal(t, []string{"a", "b"}, h.list(t, rc), "back to auto must not be served the filtered list")
}

func TestPinned_DecisionOnlyChangeMovesTheSurfaceFingerprint(t *testing.T) {
	t.Parallel()
	a := defTool(t, "a", "x")
	reg := pinnedReg(t)
	rc := routable(mcpClient(), reg)

	empty := SurfaceFingerprint(rc, nil)
	bindings := consumerBindings(rc)

	reg.PinnedTools = []registrydomain.ToolDecision{decision(t, a, registrydomain.ToolStatusApproved)}
	assert.NotEqual(t, empty, SurfaceFingerprint(rc, nil), "UpdatedAt did not move, the decision did")
	assert.NotEqual(t, bindings, consumerBindings(rc), "the watch snapshot must see it too")

	approved := SurfaceFingerprint(rc, nil)
	reg.ToolPolicy = registrydomain.ToolPolicyAuto
	assert.NotEqual(t, approved, SurfaceFingerprint(rc, nil), "leaving pinned moves it as well")

	auto := mcpRegistry(t, "auto", pinnedURL)
	fp := SurfaceFingerprint(routable(mcpClient(), auto), nil)
	assert.Equal(t, fp, SurfaceFingerprint(routable(mcpClient(), auto), nil), "auto stays stable")
}

func TestPinned_NonCacheablePathRecordsOnceForRepeatedCalls(t *testing.T) {
	t.Parallel()
	ok := defTool(t, "ok", "approved")
	reg := pinnedReg(t, decision(t, ok, registrydomain.ToolStatusApproved))
	// A per-principal registry with no principal in the context is not cacheable:
	// discovery asks the upstream on every call.
	reg.MCPTarget.Auth = &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModePassthrough}
	rec := &fakeRecorder{}
	h := newPinnedHarness(t, []Tool{ok, defTool(t, "new", "n")}, rec)
	rc := routable(mcpClient(), reg)

	for range 3 {
		assert.Equal(t, []string{"ok"}, h.list(t, rc))
	}
	assert.Equal(t, 3, h.dialer.count(pinnedURL), "the path really is uncached")
	assert.Equal(t, 1, rec.calls(), "the same candidate is reported once")
}

func TestPinned_ABlockedRecorderDoesNotDelayDiscovery(t *testing.T) {
	t.Parallel()
	ok := defTool(t, "ok", "approved")
	reg := pinnedReg(t, decision(t, ok, registrydomain.ToolStatusApproved))
	rec := &fakeRecorder{block: make(chan struct{})}
	h := newPinnedHarness(t, []Tool{ok, defTool(t, "new", "n")}, rec)
	rc := routable(mcpClient(), reg)

	done := make(chan []Tool, 1)
	go func() {
		got, _ := h.composer.ListTools(context.Background(), rc)
		done <- got
	}()
	select {
	case got := <-done:
		assert.Len(t, got, 1)
	case <-time.After(time.Second):
		t.Fatal("ListTools waited on the recorder")
	}
	require.Eventually(t, func() bool { return rec.calls() == 1 }, time.Second, time.Millisecond)

	// Shutdown cancels the in-flight Record instead of hanging on it.
	h.async.Close()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	assert.ErrorIs(t, rec.ctxErr, context.Canceled)
}

func TestAsyncPendingRecorder_DropsWhenTheQueueIsFull(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	rec := &fakeRecorder{block: make(chan struct{})}
	async := NewAsyncPendingRecorder(rec, slog.New(slog.DiscardHandler),
		WithRecorderQueueSize(1), WithRecorderMeterProvider(provider))
	t.Cleanup(async.Close)
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	cand := func(name string) []registrydomain.ToolCandidate {
		c, err := registrydomain.NewToolCandidate(name, "d", nil)
		require.NoError(t, err)
		return []registrydomain.ToolCandidate{c}
	}

	async.Submit(gw, reg, cand("one"))
	require.Eventually(t, func() bool { return rec.calls() == 1 }, time.Second, time.Millisecond) // worker is blocked on it
	async.Submit(gw, reg, cand("two"))                                                            // fills the queue
	async.Submit(gw, reg, cand("three"))                                                          // dropped

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var dropped int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "trustgate.mcp.pinned_tools.dropped" {
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					dropped += dp.Value
				}
			}
		}
	}
	assert.Equal(t, int64(1), dropped)

	// The dropped key was forgotten, so it is offered again once there is room.
	close(rec.block)
	require.Eventually(t, async.idle, time.Second, time.Millisecond)
	async.Submit(gw, reg, cand("three"))
	require.Eventually(t, func() bool { return rec.calls() == 3 }, time.Second, time.Millisecond)
}

func TestAsyncPendingRecorder_DedupeExpires(t *testing.T) {
	t.Parallel()
	now := time.Now()
	rec := &fakeRecorder{}
	async := NewAsyncPendingRecorder(rec, slog.New(slog.DiscardHandler), WithRecorderClock(func() time.Time { return now }))
	t.Cleanup(async.Close)
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	c, err := registrydomain.NewToolCandidate("a", "d", nil)
	require.NoError(t, err)

	async.Submit(gw, reg, []registrydomain.ToolCandidate{c})
	require.Eventually(t, async.idle, time.Second, time.Millisecond)
	async.Submit(gw, reg, []registrydomain.ToolCandidate{c})
	require.Eventually(t, async.idle, time.Second, time.Millisecond)
	assert.Equal(t, 1, rec.calls())

	now = now.Add(pendingDedupeTTL + time.Second)
	async.Submit(gw, reg, []registrydomain.ToolCandidate{c})
	require.Eventually(t, func() bool { return rec.calls() == 2 }, time.Second, time.Millisecond)
}

func TestAsyncPendingRecorder_NilReceiverIsInert(t *testing.T) {
	t.Parallel()
	var r *AsyncPendingRecorder
	r.Submit(ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind](), nil)
	r.Close()
}

func TestPinned_RecordsTheShelfRegistryForAnInstanceClone(t *testing.T) {
	t.Parallel()
	ok := defTool(t, "ok", "approved")
	shelf := pinnedReg(t, decision(t, ok, registrydomain.ToolStatusApproved))
	clone := *shelf
	clone.ID = ids.New[ids.RegistryKind]()
	clone.InstanceOf = shelf.ID
	rec := &fakeRecorder{}
	h := newPinnedHarness(t, []Tool{ok, defTool(t, "new", "n")}, rec)

	assert.Equal(t, []string{"ok"}, h.list(t, routable(mcpClient(), &clone)))
	require.Equal(t, 1, rec.calls())
	assert.Equal(t, shelf.ID, rec.batches[0].registryID, "the decision lives on the shelf registry")
}

// The admin API approves ToolCandidate(tool).ToolRef. The discovery filter must
// expose a tool decided that way even when its schema carries numbers a JSON
// round trip would rewrite, so what an admin approves is what the plane serves.
func TestPinned_ToolCandidateIsTheIdentityTheFilterScreensBy(t *testing.T) {
	t.Parallel()
	var tool Tool
	require.NoError(t, json.Unmarshal([]byte(`{"name":"calc","description":"d","inputSchema":{"properties":{"a":{"default":1.0},"b":{"maximum":1e3},"c":{"const":9007199254740993}}}}`), &tool))
	cand, err := ToolCandidate(tool)
	require.NoError(t, err)
	reg := pinnedReg(t, registrydomain.ToolDecision{Name: cand.Name, Fingerprint: cand.Fingerprint, Status: registrydomain.ToolStatusApproved})
	h := newPinnedHarness(t, []Tool{tool}, &fakeRecorder{})

	assert.Equal(t, []string{"calc"}, h.list(t, routable(mcpClient(), reg)))
}
