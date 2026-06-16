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
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
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
	writeMeta bool
	validErr  error
}

func (f *fakePlugin) Name() string                        { return f.name }
func (f *fakePlugin) MandatoryStages() []policy.Stage     { return f.stages }
func (f *fakePlugin) SupportedStages() []policy.Stage     { return f.stages }
func (f *fakePlugin) SupportedModes() []policy.Mode       { return []policy.Mode{policy.ModeEnforce} }
func (f *fakePlugin) ValidateConfig(map[string]any) error { return f.validErr }

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
	return f.result, f.err
}

type polSpec struct {
	slug     string
	enabled  bool
	priority int
	parallel bool
	global   bool
	stages   []policy.Stage
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
			Stages:   s.stages,
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
func (s *scopeCapturePlugin) ValidateConfig(map[string]any) error { return nil }
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

	plan := NewStagePlan(reg, policies(t, polSpec{slug: "rate", enabled: true}))
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

func TestExecutor_RunStage_PropagatesGlobalScopeFromPlan(t *testing.T) {
	p := &scopeCapturePlugin{name: "rate", seen: make(chan ExecInput, 1)}
	reg := newRegistry(t, p)
	exec := NewExecutor(reg, nil)

	plan := NewStagePlan(reg, policies(t, polSpec{slug: "rate", enabled: true, global: true}))
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
