package plugins

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePlugin struct {
	name     string
	stages   []policy.Stage
	result   *Result
	err      error
	delay    time.Duration
	calls    *int32
	onExec   func()
	validErr error
}

func (f *fakePlugin) Name() string                        { return f.name }
func (f *fakePlugin) Stages() []policy.Stage              { return f.stages }
func (f *fakePlugin) ValidateConfig(map[string]any) error { return f.validErr }

func (f *fakePlugin) Execute(ctx context.Context, _ ExecInput) (*Result, error) {
	if f.calls != nil {
		atomic.AddInt32(f.calls, 1)
	}
	if f.onExec != nil {
		f.onExec()
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

func policyWith(t *testing.T, plugins ...policy.Plugin) *policy.Policy {
	t.Helper()
	return &policy.Policy{Name: "p", Plugins: plugins}
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

	pol := policyWith(t,
		policy.Plugin{Name: "third", Enabled: true, Priority: 30},
		policy.Plugin{Name: "first", Enabled: true, Priority: 10},
		policy.Plugin{Name: "second", Enabled: true, Priority: 20},
	)

	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: []*policy.Policy{pol},
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

	pol := policyWith(t,
		policy.Plugin{Name: "rate", Enabled: false, Priority: 1}, // disabled
		policy.Plugin{Name: "token", Enabled: true, Priority: 2}, // wrong stage
		policy.Plugin{Name: "ghost", Enabled: true, Priority: 3}, // unknown
	)

	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: []*policy.Policy{pol},
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
	pol := policyWith(t,
		policy.Plugin{Name: "cache", Enabled: true, Priority: 1},
		policy.Plugin{Name: "after", Enabled: true, Priority: 2},
	)

	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: []*policy.Policy{pol},
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
		Policies: []*policy.Policy{policyWith(t, policy.Plugin{Name: "rate", Enabled: true})},
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

	pol := policyWith(t,
		policy.Plugin{Name: "a", Enabled: true, Priority: 1, Parallel: true},
		policy.Plugin{Name: "b", Enabled: true, Priority: 1, Parallel: true},
		policy.Plugin{Name: "c", Enabled: true, Priority: 1, Parallel: true},
	)

	resp := &infracontext.ResponseContext{}
	start := time.Now()
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: []*policy.Policy{pol},
		Response: resp,
	})
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
	// Three 50ms plugins run concurrently in well under 150ms.
	assert.Less(t, elapsed, 120*time.Millisecond)
	assert.Len(t, resp.Headers, 3)
}

func TestExecutor_RunStage_MergesHeadersInOrder(t *testing.T) {
	a := &fakePlugin{name: "a", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{Headers: map[string][]string{"Vary": {"Origin"}}}}
	b := &fakePlugin{name: "b", stages: []policy.Stage{policy.StagePreResponse}, result: &Result{Headers: map[string][]string{"Vary": {"Accept"}}}}
	reg := newRegistry(t, a, b)
	exec := NewExecutor(reg, nil)

	resp := &infracontext.ResponseContext{}
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreResponse,
		Policies: []*policy.Policy{policyWith(t, policy.Plugin{Name: "a", Enabled: true, Priority: 1}, policy.Plugin{Name: "b", Enabled: true, Priority: 2})},
		Response: resp,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"Origin", "Accept"}, resp.Headers["Vary"])
}

func TestExecutor_RunStage_RecordsPluginSpanOnTrace(t *testing.T) {
	p := &fakePlugin{name: "rate", stages: []policy.Stage{policy.StagePreRequest}, result: &Result{StatusCode: 200}}
	reg := newRegistry(t, p)
	exec := NewExecutor(reg, nil)

	rt := trace.New("t", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	_, err := exec.RunStage(ctx, StageInput{
		Stage:    policy.StagePreRequest,
		Policies: []*policy.Policy{policyWith(t, policy.Plugin{Name: "rate", Enabled: true})},
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
