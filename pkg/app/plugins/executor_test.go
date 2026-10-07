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

package plugins

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePlugin struct {
	name      string
	stages    []policy.Stage
	result    *Result
	err       error
	delay     time.Duration
	calls     *int32
	onExec    func()
	execFn    func(in ExecInput) (*Result, error)
	writeMeta bool
	validErr  error
	mutReq    bool
	mutResp   bool
	mutMeta   bool
}

func (f *fakePlugin) Name() string                        { return f.name }
func (f *fakePlugin) MandatoryStages() []policy.Stage     { return f.stages }
func (f *fakePlugin) SupportedStages() []policy.Stage     { return f.stages }
func (f *fakePlugin) SupportedModes() []policy.Mode       { return []policy.Mode{policy.ModeEnforce} }
func (f *fakePlugin) SupportedProtocols() []Protocol      { return []Protocol{ProtocolLLM} }
func (f *fakePlugin) ValidateConfig(map[string]any) error { return f.validErr }
func (f *fakePlugin) MutatesRequestBody() bool            { return f.mutReq }
func (f *fakePlugin) MutatesResponseBody() bool           { return f.mutResp }
func (f *fakePlugin) MutatesMetadata() bool               { return f.mutMeta }

func (f *fakePlugin) Execute(ctx context.Context, in ExecInput) (*Result, error) {
	if f.calls != nil {
		atomic.AddInt32(f.calls, 1)
	}
	if f.onExec != nil {
		f.onExec()
	}
	// Simulate a plugin that writes the shared response metadata (e.g. semantic
	// cache). Under a parallel batch this must hit an isolated copy, never the
	// shared map, or the race detector would flag a concurrent map write.
	if f.writeMeta && in.Response != nil {
		if in.Response.Metadata == nil {
			in.Response.Metadata = make(map[string]interface{})
		}
		in.Response.Metadata[f.name] = true
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.execFn != nil {
		return f.execFn(in)
	}
	return f.result, f.err
}

type polSpec struct {
	slug     string
	enabled  bool
	priority int
	parallel bool
	global   bool
	mcpWide  bool
	stages   []policy.Stage
	mode     policy.Mode
}

func policies(t *testing.T, specs ...polSpec) []*policy.Policy {
	t.Helper()
	out := make([]*policy.Policy, 0, len(specs))
	for _, s := range specs {
		out = append(out, &policy.Policy{
			ID:       ids.New[ids.PolicyKind](),
			Name:     s.slug,
			Slug:     s.slug,
			Enabled:  s.enabled,
			Priority: s.priority,
			Parallel: s.parallel,
			Global:   s.global,
			MCPWide:  s.mcpWide,
			Stages:   s.stages,
			Mode:     s.mode,
		})
	}
	return out
}

// scopeCapturePlugin records the RuntimeScope it was executed with so tests can
// assert the executor derived it from the policy and the request.
type scopeCapturePlugin struct {
	name string
	seen chan ExecInput
}

func (s *scopeCapturePlugin) Name() string { return s.name }
func (s *scopeCapturePlugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}
func (s *scopeCapturePlugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}
func (s *scopeCapturePlugin) SupportedModes() []policy.Mode       { return []policy.Mode{policy.ModeEnforce} }
func (s *scopeCapturePlugin) SupportedProtocols() []Protocol      { return []Protocol{ProtocolLLM} }
func (s *scopeCapturePlugin) ValidateConfig(map[string]any) error { return nil }
func (s *scopeCapturePlugin) MutatesRequestBody() bool            { return false }
func (s *scopeCapturePlugin) MutatesResponseBody() bool           { return false }
func (s *scopeCapturePlugin) MutatesMetadata() bool               { return false }
func (s *scopeCapturePlugin) Execute(_ context.Context, in ExecInput) (*Result, error) {
	s.seen <- in
	return &Result{StatusCode: 200}, nil
}

func newRegistry(t *testing.T, ps ...Plugin) Registry {
	t.Helper()
	reg := NewRegistry()
	for _, p := range ps {
		require.NoError(t, reg.Register(p))
	}
	return reg
}

func TestExecutor_RunStage_EmptyChain(t *testing.T) {
	reg := NewRegistry()
	exec := NewExecutor(reg, nil)

	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: nil,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	require.False(t, out.ShortCircuit)
}

func TestExecutor_RunStage_OrdersByPriority(t *testing.T) {
	var order []string
	mk := func(name string) *fakePlugin {
		return &fakePlugin{
			name:   name,
			stages: []policy.Stage{policy.StagePreRequest},
			result: &Result{StatusCode: 200},
			onExec: func() { order = append(order, name) },
		}
	}
	reg := newRegistry(t, mk("first"), mk("second"), mk("third"))
	exec := NewExecutor(reg, nil)

	pols := policies(t,
		polSpec{slug: "third", enabled: true, priority: 30},
		polSpec{slug: "first", enabled: true, priority: 10},
		polSpec{slug: "second", enabled: true, priority: 20},
	)

	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"first", "second", "third"}, order)
}

func TestExecutor_RunStage_SkipsDisabledUnknownAndWrongStage(t *testing.T) {
	calls := int32(0)
	preReq := &fakePlugin{
		name:   "rate",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200},
		calls:  &calls,
	}
	postOnly := &fakePlugin{
		name:   "token",
		stages: []policy.Stage{policy.StagePostResponse},
		result: &Result{StatusCode: 200},
		calls:  &calls,
	}
	reg := newRegistry(t, preReq, postOnly)
	exec := NewExecutor(reg, nil)

	pols := policies(t,
		polSpec{slug: "rate", enabled: false, priority: 1}, // disabled
		polSpec{slug: "token", enabled: true, priority: 2}, // wrong stage
		polSpec{slug: "ghost", enabled: true, priority: 3}, // unknown
	)

	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	require.False(t, out.ShortCircuit)
	assert.Equal(t, int32(0), atomic.LoadInt32(&calls))
}

func TestExecutor_RunStage_ShortCircuitStopsChain(t *testing.T) {
	calls := int32(0)
	hit := &fakePlugin{
		name:   "cache",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200, Body: []byte("cached"), Headers: map[string][]string{"X-Cache-Status": {"HIT"}}, StopUpstream: true},
		calls:  &calls,
	}
	never := &fakePlugin{
		name:   "after",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200},
		calls:  &calls,
	}
	reg := newRegistry(t, hit, never)
	exec := NewExecutor(reg, nil)

	resp := &infracontext.ResponseContext{}
	pols := policies(t,
		polSpec{slug: "cache", enabled: true, priority: 1},
		polSpec{slug: "after", enabled: true, priority: 2},
	)

	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: resp,
	})
	require.NoError(t, err)
	require.True(t, out.ShortCircuit)
	assert.Equal(t, 200, out.StatusCode)
	assert.Equal(t, []byte("cached"), out.Body)
	assert.Equal(t, []string{"HIT"}, out.Headers["X-Cache-Status"])
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls)) // "after" never ran
}

func TestExecutor_RunStage_RequestBodyRewrite(t *testing.T) {
	rewrite := &fakePlugin{
		name:   "strip",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200, RequestBody: []byte(`{"stripped":true}`)},
	}
	reg := newRegistry(t, rewrite)
	exec := NewExecutor(reg, nil)

	req := &infracontext.RequestContext{Body: []byte(`{"original":true}`)}
	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: policies(t, polSpec{slug: "strip", enabled: true}),
		Request:  req,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	require.False(t, out.ShortCircuit)
	assert.Equal(t, []byte(`{"stripped":true}`), req.Body)
}

func TestExecutor_RunStage_PluginErrorPropagates(t *testing.T) {
	reject := &fakePlugin{
		name:   "rate",
		stages: []policy.Stage{policy.StagePreRequest},
		err:    &PluginError{StatusCode: 429, Message: "rate limit exceeded"},
	}
	reg := newRegistry(t, reject)
	exec := NewExecutor(reg, nil)

	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: policies(t, polSpec{slug: "rate", enabled: true}),
		Response: &infracontext.ResponseContext{},
	})
	require.Error(t, err)
	pe, ok := AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
}

func TestExecutor_RunStage_ParallelBatchRunsConcurrently(t *testing.T) {
	calls := int32(0)
	mk := func(name string) *fakePlugin {
		return &fakePlugin{
			name:   name,
			stages: []policy.Stage{policy.StagePreRequest},
			result: &Result{StatusCode: 200, Headers: map[string][]string{"X-" + name: {"1"}}},
			delay:  50 * time.Millisecond,
			calls:  &calls,
		}
	}
	reg := newRegistry(t, mk("a"), mk("b"), mk("c"))
	exec := NewExecutor(reg, nil)

	pols := policies(t,
		polSpec{slug: "a", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "b", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "c", enabled: true, priority: 1, parallel: true},
	)

	resp := &infracontext.ResponseContext{}
	start := time.Now()
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: resp,
	})
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
	// Three 50ms plugins run concurrently in well under 150ms.
	assert.Less(t, elapsed, 120*time.Millisecond)
	assert.Len(t, resp.Headers, 3)
}

func TestExecutor_RunStage_ParallelBatchIsolatesMetadata(t *testing.T) {
	mk := func(name string) *fakePlugin {
		return &fakePlugin{
			name:      name,
			stages:    []policy.Stage{policy.StagePreRequest},
			result:    &Result{StatusCode: 200},
			writeMeta: true,
		}
	}
	reg := newRegistry(t, mk("a"), mk("b"), mk("c"))
	exec := NewExecutor(reg, nil)

	pols := policies(t,
		polSpec{slug: "a", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "b", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "c", enabled: true, priority: 1, parallel: true},
	)

	resp := &infracontext.ResponseContext{}
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Request:  &infracontext.RequestContext{},
		Response: resp,
	})
	require.NoError(t, err)
	// Each parallel plugin wrote to its isolated response; mergeIsolated folds
	// every write back into the shared map (run under -race to prove no panic).
	assert.Equal(t, true, resp.Metadata["a"])
	assert.Equal(t, true, resp.Metadata["b"])
	assert.Equal(t, true, resp.Metadata["c"])
}

func TestExecutor_RunStage_UsesPrecomputedPlan(t *testing.T) {
	calls := int32(0)
	p := &fakePlugin{
		name:   "rate",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200},
		calls:  &calls,
	}
	reg := newRegistry(t, p)
	exec := NewExecutor(reg, nil)

	plan := NewStagePlan(reg, policies(t, polSpec{slug: "rate", enabled: true}), nil)
	// Policies is intentionally omitted: the executor must run purely from the
	// precomputed plan.
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Plan:     plan,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

func TestExecutor_RunStage_MergesHeadersInOrder(t *testing.T) {
	a := &fakePlugin{name: "a", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{Headers: map[string][]string{"Vary": {"Origin"}}}}
	b := &fakePlugin{name: "b", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{Headers: map[string][]string{"Vary": {"Accept"}}}}
	reg := newRegistry(t, a, b)
	exec := NewExecutor(reg, nil)

	resp := &infracontext.ResponseContext{}
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage: policy.StagePreResponse,
		Policies: policies(t,
			polSpec{slug: "a", enabled: true, priority: 1},
			polSpec{slug: "b", enabled: true, priority: 2},
		),
		Response: resp,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"Origin", "Accept"}, resp.Headers["Vary"])
}

func TestExecutor_RunStage_PropagatesConsumerScope(t *testing.T) {
	p := &scopeCapturePlugin{name: "rate", seen: make(chan ExecInput, 1)}
	reg := newRegistry(t, p)
	exec := NewExecutor(reg, nil)

	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: policies(t, polSpec{slug: "rate", enabled: true, global: false}),
		Request:  &infracontext.RequestContext{GatewayID: "gw-1", ConsumerID: "c-1"},
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)

	in := <-p.seen
	assert.False(t, in.Scope.Global)
	assert.Equal(t, "gw-1", in.Scope.GatewayID)
	assert.Equal(t, "c-1", in.Scope.ConsumerID)

	dimension, id, err := in.Scope.Subject()
	require.NoError(t, err)
	assert.Equal(t, "consumer", dimension)
	assert.Equal(t, "c-1", id)
}

func TestScopeFromRequest_Key(t *testing.T) {
	tests := []struct {
		name          string
		req           *infracontext.RequestContext
		wantDimension string
		wantID        string
	}{
		{name: "owned key counts per owner", req: &infracontext.RequestContext{ConsumerID: "c-1", AuthID: "auth-1", OwnerID: "alice"}, wantDimension: "owner", wantID: "alice"},
		{name: "application key counts per auth", req: &infracontext.RequestContext{ConsumerID: "c-1", AuthID: "auth-1"}, wantDimension: "auth", wantID: "auth-1"},
		{name: "no auth is not counted", req: &infracontext.RequestContext{GatewayID: "gw-1", ConsumerID: "c-1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dimension, id, ok := scopeFromRequest(tt.req, true).Key()
			assert.Equal(t, tt.wantDimension != "", ok)
			assert.Equal(t, tt.wantDimension, dimension)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

func TestScopeFromRequest_CarriesTheKeyBudget(t *testing.T) {
	budget := &authdomain.KeyBudget{Max: 50, Unit: authdomain.BudgetUnitDollars, TimeWindow: authdomain.BudgetWindowCalendarMonth}
	assert.Same(t, budget, scopeFromRequest(&infracontext.RequestContext{AuthID: "auth-1", OwnerID: "alice", KeyBudget: budget}, true).KeyBudget)
	assert.Nil(t, scopeFromRequest(&infracontext.RequestContext{AuthID: "auth-1", OwnerID: "alice"}, true).KeyBudget)
	assert.Nil(t, scopeFromRequest(nil, true).KeyBudget)
}

func TestExecutor_RunStage_PropagatesGlobalScopeFromPlan(t *testing.T) {
	p := &scopeCapturePlugin{name: "rate", seen: make(chan ExecInput, 1)}
	reg := newRegistry(t, p)
	exec := NewExecutor(reg, nil)

	plan := NewStagePlan(reg, policies(t, polSpec{slug: "rate", enabled: true, global: true}), nil)
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Plan:     plan,
		Request:  &infracontext.RequestContext{GatewayID: "gw-1", ConsumerID: "c-1"},
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)

	in := <-p.seen
	assert.True(t, in.Scope.Global, "a global policy must propagate Global through the precomputed plan")

	dimension, id, err := in.Scope.Subject()
	require.NoError(t, err)
	assert.Equal(t, "global", dimension)
	assert.Equal(t, "gw-1", id)
}

func TestExecutor_RunStage_MCPWidePolicyRunsWithGatewayWideScope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		viaPlan bool
	}{
		{name: "precomputed plan", viaPlan: true},
		{name: "chain rebuilt from policies"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &scopeCapturePlugin{name: "rate", seen: make(chan ExecInput, 1)}
			reg := newRegistry(t, p)
			pols := policies(t, polSpec{slug: "rate", enabled: true, mcpWide: true})
			in := StageInput{
				Stage:    policy.StagePreRequest,
				Request:  &infracontext.RequestContext{GatewayID: "gw-1", ConsumerID: "c-1"},
				Response: &infracontext.ResponseContext{},
			}
			if tc.viaPlan {
				in.Plan = NewStagePlan(reg, pols, nil)
			} else {
				in.Policies = pols
			}

			_, err := NewExecutor(reg, nil).RunStage(context.Background(), in)
			require.NoError(t, err)

			got := <-p.seen
			assert.True(t, got.Scope.Global, "an MCP-wide policy keeps one budget for the gateway, like a global one")
			dimension, id, err := got.Scope.Subject()
			require.NoError(t, err)
			assert.Equal(t, "global", dimension)
			assert.Equal(t, "gw-1", id)
		})
	}
}

func TestExecutor_RunStage_RecordsPluginSpanOnTrace(t *testing.T) {
	p := &fakePlugin{name: "rate", stages: []policy.Stage{policy.StagePreRequest}, result: &Result{StatusCode: 200}}
	reg := newRegistry(t, p)
	exec := NewExecutor(reg, nil)

	rt := trace.New("t", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	_, err := exec.RunStage(ctx, StageInput{
		Stage:    policy.StagePreRequest,
		Policies: policies(t, polSpec{slug: "rate", enabled: true}),
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1)
	assert.Equal(t, trace.SpanPlugin, spans[0].Type)
	assert.Equal(t, "rate", spans[0].Name)
	require.NotNil(t, spans[0].Plugin)
	assert.Equal(t, string(policy.StagePreRequest), spans[0].Plugin.Stage)
	assert.Equal(t, 200, spans[0].StatusCode())
}

func touchMetadata(m map[string]interface{}) {
	for _, v := range m {
		if inner, ok := v.(map[string]interface{}); ok {
			for _, iv := range inner {
				_ = iv
			}
		}
	}
}

func TestExecutor_RunStage_ParallelReqBodyMutatorsSplitNoLostUpdate(t *testing.T) {
	calls := int32(0)
	mk := func(name, body string) *fakePlugin {
		return &fakePlugin{
			name:   name,
			stages: []policy.Stage{policy.StagePreRequest},
			result: &Result{StatusCode: 200, RequestBody: []byte(body)},
			calls:  &calls,
			mutReq: true,
		}
	}
	reg := newRegistry(t, mk("a_req", `{"mutator":"a"}`), mk("b_req", `{"mutator":"b"}`))
	exec := NewExecutor(reg, nil)

	req := &infracontext.RequestContext{Body: []byte(`{"mutator":"none"}`)}
	pols := policies(t,
		polSpec{slug: "a_req", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "b_req", enabled: true, priority: 1, parallel: true},
	)
	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Request:  req,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	require.False(t, out.ShortCircuit)
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "both request-body mutators must run; the planner splits them so neither write is dropped")
	assert.Equal(t, []byte(`{"mutator":"b"}`), req.Body, "two same-priority request-body mutators are forced sequential; the last block in priority,slug order wins deterministically")
}

func TestExecutor_RunStage_SequentialBlocksFoldRequestBody(t *testing.T) {
	mk := func(name, suffix string) *fakePlugin {
		return &fakePlugin{
			name:   name,
			stages: []policy.Stage{policy.StagePreRequest},
			mutReq: true,
			execFn: func(in ExecInput) (*Result, error) {
				folded := append(append([]byte(nil), in.Request.Body...), suffix...)
				return &Result{StatusCode: 200, RequestBody: folded}, nil
			},
		}
	}
	reg := newRegistry(t, mk("a_req", "+a"), mk("b_req", "+b"))
	exec := NewExecutor(reg, nil)

	req := &infracontext.RequestContext{Body: []byte("start")}
	pols := policies(t,
		polSpec{slug: "a_req", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "b_req", enabled: true, priority: 1, parallel: true},
	)
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Request:  req,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("start+a+b"), req.Body, "the later sequential block must observe the earlier block's folded body, not the original request body")
}

func TestExecutor_RunStage_DeterministicBatchOrdering(t *testing.T) {
	mk := func(name string) *fakePlugin {
		return &fakePlugin{name: name, stages: []policy.Stage{policy.StagePreRequest}, result: &Result{StatusCode: 200}}
	}
	reg := newRegistry(t, mk("c"), mk("a"), mk("b"))

	pols := policies(t,
		polSpec{slug: "c", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "a", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "b", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "a", enabled: true, priority: 1, parallel: true},
	)

	var first [][]string
	for run := 0; run < 5; run++ {
		plan := NewStagePlan(reg, pols, nil)
		batches := plan.batchesFor(policy.StagePreRequest)
		require.Len(t, batches, 1, "non-mutating parallel entries at equal priority collapse into one batch")

		slugs := batchSlugs(batches)
		if run == 0 {
			assert.Equal(t, [][]string{{"a", "a", "b", "c"}}, slugs, "entries must order by priority then slug")
			first = slugs
		}
		assert.Equal(t, first, slugs, "batch composition must be identical across repeated planning")

		var aIDs []string
		for _, entry := range batches[0] {
			if entry.config.Slug == "a" {
				aIDs = append(aIDs, entry.config.ID)
			}
		}
		require.Len(t, aIDs, 2)
		assert.Less(t, aIDs[0], aIDs[1], "ties at equal priority and slug break by ascending id")
	}
}

func TestExecutor_RunStage_ParallelMetadataWriterReadersRaceSafe(t *testing.T) {
	writer := &fakePlugin{
		name:    "a_meta",
		stages:  []policy.Stage{policy.StagePreRequest},
		mutMeta: true,
		delay:   5 * time.Millisecond,
		execFn: func(in ExecInput) (*Result, error) {
			if in.Response.Metadata == nil {
				in.Response.Metadata = make(map[string]interface{})
			}
			in.Response.Metadata["written"] = map[string]interface{}{"by": "a_meta"}
			return &Result{StatusCode: 200}, nil
		},
	}
	reader := func(name string) *fakePlugin {
		return &fakePlugin{
			name:   name,
			stages: []policy.Stage{policy.StagePreRequest},
			delay:  5 * time.Millisecond,
			execFn: func(in ExecInput) (*Result, error) {
				touchMetadata(in.Response.Metadata)
				return &Result{StatusCode: 200}, nil
			},
		}
	}
	bodyMutator := &fakePlugin{
		name:   "d_body",
		stages: []policy.Stage{policy.StagePreRequest},
		mutReq: true,
		delay:  5 * time.Millisecond,
		result: &Result{StatusCode: 200, RequestBody: []byte(`{"mutated":true}`)},
	}
	reg := newRegistry(t, writer, reader("b_read"), reader("c_read"), bodyMutator)
	exec := NewExecutor(reg, nil)

	req := &infracontext.RequestContext{Body: []byte(`{"mutated":false}`)}
	resp := &infracontext.ResponseContext{Metadata: map[string]interface{}{"shared": map[string]interface{}{"k": "v"}}}
	pols := policies(t,
		polSpec{slug: "a_meta", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "b_read", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "c_read", enabled: true, priority: 1, parallel: true},
		polSpec{slug: "d_body", enabled: true, priority: 1, parallel: true},
	)
	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Request:  req,
		Response: resp,
	})
	require.NoError(t, err)
	require.False(t, out.ShortCircuit)
	assert.Equal(t, []byte(`{"mutated":true}`), req.Body, "the single body mutator's write is folded into the request")
	assert.Equal(t, map[string]interface{}{"by": "a_meta"}, resp.Metadata["written"], "the single metadata writer's nested write is merged back")
	assert.Equal(t, map[string]interface{}{"k": "v"}, resp.Metadata["shared"], "pre-existing nested metadata read concurrently must survive untouched")
}

// newGuardrailStylePlugin builds a fake plugin whose Execute mirrors exactly
// what an external guardrail (azure_content_safety, bedrock_guardrail,
// google_model_armor, openai_moderation) does on a transport failure: it
// hands the failure to HandleExternalFailure and returns whatever that
// decides, mode by mode. It exists so this test exercises the real
// executor/mode contract rather than a stand-in for it.
func newGuardrailStylePlugin(name string) *fakePlugin {
	return &fakePlugin{
		name:   name,
		stages: []policy.Stage{policy.StagePreRequest},
		execFn: func(in ExecInput) (*Result, error) {
			outcome := HandleExternalFailure(ExternalFailure{
				Plugin: name,
				Stage:  in.Stage,
				Mode:   in.Mode,
				Reason: FailureTransport,
				Err:    context.DeadlineExceeded,
			})
			return outcome.Result, outcome.Err
		},
	}
}

func TestExecutor_RunStage_EnforceGuardrailFailureLetsLaterPluginRun(t *testing.T) {
	calls := int32(0)
	guardrail := newGuardrailStylePlugin("guardrail")
	after := &fakePlugin{
		name:   "after",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200},
		calls:  &calls,
	}
	reg := newRegistry(t, guardrail, after)
	exec := NewExecutor(reg, nil)

	pols := policies(t,
		polSpec{slug: "guardrail", enabled: true, priority: 1, mode: policy.ModeEnforce},
		polSpec{slug: "after", enabled: true, priority: 2, mode: policy.ModeEnforce},
	)
	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	require.False(t, out.ShortCircuit)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "RUN-1792: enforce fails open too, so the later plugin still runs")
}

func TestExecutor_RunStage_ObserveGuardrailFailureLetsLaterPluginRun(t *testing.T) {
	calls := int32(0)
	guardrail := newGuardrailStylePlugin("guardrail")
	after := &fakePlugin{
		name:   "after",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200},
		calls:  &calls,
	}
	reg := newRegistry(t, guardrail, after)
	exec := NewExecutor(reg, nil)

	pols := policies(t,
		polSpec{slug: "guardrail", enabled: true, priority: 1, mode: policy.ModeObserve},
		polSpec{slug: "after", enabled: true, priority: 2, mode: policy.ModeObserve},
	)
	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	require.False(t, out.ShortCircuit)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "observe fails open, so the later plugin still runs")
}

// TestExecutor_RunStage_ObserveNonPluginErrorFailsOpen is the executor's own
// safety net (RUN-1675), for a plugin that returns a plain, non-*PluginError
// error without going through HandleExternalFailure/HandleCounterFailure
// itself — a counter-store outage that slipped past its own fail-open
// handling, or any other plugin that never learned the mode-aware pattern.
// Observe never blocks, so runOne must swallow the error, record failed_open
// on the plugin's own span, and let the chain continue, mirroring what
// RunStreamSegment already does for observe-mode stream entries. The error
// is deliberately a plain transport-style error, not a context error: this
// safety net's ctx.Err() guard (see the canceled-context test below) must not
// accidentally also swallow a genuine failure that merely happens to be a
// context.DeadlineExceeded the plugin manufactured itself with its own timer,
// so the fixture here is unambiguous either way.
func TestExecutor_RunStage_ObserveNonPluginErrorFailsOpen(t *testing.T) {
	calls := int32(0)
	transportErr := errors.New("transport down")
	broken := &fakePlugin{
		name:   "broken",
		stages: []policy.Stage{policy.StagePreRequest},
		err:    transportErr,
	}
	after := &fakePlugin{
		name:   "after",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200},
		calls:  &calls,
	}
	reg := newRegistry(t, broken, after)
	exec := NewExecutor(reg, nil)

	rt := trace.New("t", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	pols := policies(t,
		polSpec{slug: "broken", enabled: true, priority: 1, mode: policy.ModeObserve},
		polSpec{slug: "after", enabled: true, priority: 2, mode: policy.ModeObserve},
	)
	out, err := exec.RunStage(ctx, StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err, "observe must fail open on a plain error, not surface it")
	require.NotNil(t, out)
	require.False(t, out.ShortCircuit)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "the chain must continue past the failed-open entry")

	spans := rt.Spans()
	require.Len(t, spans, 2)
	require.NotNil(t, spans[0].Plugin)
	assert.Equal(t, "failed_open", spans[0].Plugin.Decision)
	assert.Contains(t, spans[0].Error(), "transport down",
		"the original cause must still be visible on the span, not just swallowed into a 200")
}

// TestExecutor_RunStage_EnforceNonPluginErrorStillFails proves the safety net
// is scoped to non-blocking modes only: an enforce entry returning a plain
// error is unchanged behaviour — it still stops the chain with that error,
// exactly like today.
func TestExecutor_RunStage_EnforceNonPluginErrorStillFails(t *testing.T) {
	calls := int32(0)
	transportErr := errors.New("transport down")
	broken := &fakePlugin{
		name:   "broken",
		stages: []policy.Stage{policy.StagePreRequest},
		err:    transportErr,
	}
	after := &fakePlugin{
		name:   "after",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &Result{StatusCode: 200},
		calls:  &calls,
	}
	reg := newRegistry(t, broken, after)
	exec := NewExecutor(reg, nil)

	pols := policies(t,
		polSpec{slug: "broken", enabled: true, priority: 1, mode: policy.ModeEnforce},
		polSpec{slug: "after", enabled: true, priority: 2, mode: policy.ModeEnforce},
	)
	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	})
	require.Nil(t, out)
	require.ErrorIs(t, err, transportErr)
	assert.Equal(t, int32(0), atomic.LoadInt32(&calls), "a later plugin must not run once enforce fails the chain")
}

// TestExecutor_RunStage_ObserveCanceledContextIsNotFailedOpen proves item 1 of
// the RUN-1675 review: a ctx the caller itself canceled (or let deadline out)
// is not this plugin failing — it is the caller giving up on the request for
// its own reasons. The safety net must not relabel that as failed_open; it
// must propagate the ctx error unchanged, exactly as it would have before
// this safety net existed.
func TestExecutor_RunStage_ObserveCanceledContextIsNotFailedOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rt := trace.New("t", trace.Metadata{})
	tctx := trace.NewContext(ctx, rt)

	broken := &fakePlugin{
		name:   "broken",
		stages: []policy.Stage{policy.StagePreRequest},
		err:    context.Canceled,
	}
	reg := newRegistry(t, broken)
	exec := NewExecutor(reg, nil)

	pols := policies(t, polSpec{slug: "broken", enabled: true, priority: 1, mode: policy.ModeObserve})
	out, err := exec.RunStage(tctx, StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	})
	require.Nil(t, out)
	require.ErrorIs(t, err, context.Canceled, "a canceled ctx must propagate its error, not be swallowed into a 200")

	spans := rt.Spans()
	require.Len(t, spans, 1)
	decision := ""
	if spans[0].Plugin != nil {
		decision = spans[0].Plugin.Decision
	}
	assert.NotEqual(t, "failed_open", decision, "a caller cancellation must not be recorded as this plugin failing open")
}

// TestExecutor_RunStage_ParallelBatchSiblingCancellationIsNotFailedOpen is the
// review's parallel-batch scenario: an enforce sibling in the same batch
// blocks (errors immediately), which cancels errgroup's shared gctx; an
// observe sibling is still sleeping and picks that cancellation up as
// ctx.Err() != nil through its own select on ctx.Done(). That must not be
// recorded as the observe entry itself failing open — it never got the
// chance to run to a real outcome at all.
func TestExecutor_RunStage_ParallelBatchSiblingCancellationIsNotFailedOpen(t *testing.T) {
	blockErr := errors.New("enforce sibling blocked")
	enforceEntry := &fakePlugin{
		name:   "enforce-blocker",
		stages: []policy.Stage{policy.StagePreRequest},
		err:    blockErr,
	}
	observeEntry := &fakePlugin{
		name:   "observe-slow",
		stages: []policy.Stage{policy.StagePreRequest},
		delay:  50 * time.Millisecond,
	}
	reg := newRegistry(t, enforceEntry, observeEntry)
	exec := NewExecutor(reg, nil)

	rt := trace.New("t", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	pols := policies(t,
		polSpec{slug: "enforce-blocker", enabled: true, priority: 1, parallel: true, mode: policy.ModeEnforce},
		polSpec{slug: "observe-slow", enabled: true, priority: 1, parallel: true, mode: policy.ModeObserve},
	)
	_, err := exec.RunStage(ctx, StageInput{
		Stage:    policy.StagePreRequest,
		Policies: pols,
		Response: &infracontext.ResponseContext{},
	})
	require.Error(t, err, "the enforce sibling's own error must still surface")

	spans := rt.Spans()
	require.Len(t, spans, 2)
	for _, span := range spans {
		if span.Name != "observe-slow" {
			continue
		}
		decision := ""
		if span.Plugin != nil {
			decision = span.Plugin.Decision
		}
		assert.NotEqual(t, "failed_open", decision,
			"a sibling's cancellation must not be recorded as this plugin failing open")
	}
}
