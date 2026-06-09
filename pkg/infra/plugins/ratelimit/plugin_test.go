package ratelimit

import (
	"context"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPlugin(t *testing.T) (*Plugin, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	fixed := time.Unix(1_700_000_000, 0)
	seq := 0
	p := New(rdb,
		WithClock(func() time.Time { return fixed }),
		WithIDGenerator(func() string { seq++; return string(rune('a' + seq)) }),
	)
	return p, mr
}

func consumerScope(consumerID string) appplugins.RuntimeScope {
	return appplugins.RuntimeScope{ConsumerID: consumerID, GatewayID: "gw-1"}
}

func globalScope() appplugins.RuntimeScope {
	return appplugins.RuntimeScope{GatewayID: "gw-1", Global: true}
}

func execInput(settings map[string]any, scope appplugins.RuntimeScope) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    policy.StagePreRequest,
		Config:   policy.PluginConfig{ID: "plugin-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Scope:    scope,
		Request:  &infracontext.RequestContext{},
		Response: &infracontext.ResponseContext{},
	}
}

func limitSettings(limit int, window string) map[string]any {
	return map[string]any{"limit": limit, "window": window}
}

func headerSettings(limit int, window, header string) map[string]any {
	s := limitSettings(limit, window)
	s["group_by_header"] = header
	return s
}

func execInputHdr(settings map[string]any, scope appplugins.RuntimeScope, headers map[string][]string) appplugins.ExecInput {
	in := execInput(settings, scope)
	in.Request = &infracontext.RequestContext{Headers: headers}
	return in
}

func TestPlugin_Stages(t *testing.T) {
	p := New(nil)
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
	assert.Equal(t, PluginName, p.Name())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name:     "valid",
			settings: limitSettings(5, "1m"),
		},
		{
			name:     "missing limit",
			settings: map[string]any{"window": "1m"},
			wantErr:  true,
		},
		{
			name:     "non-positive limit",
			settings: limitSettings(0, "1m"),
			wantErr:  true,
		},
		{
			name:     "missing window",
			settings: map[string]any{"limit": 5},
			wantErr:  true,
		},
		{
			name:     "bad window",
			settings: limitSettings(5, "nope"),
			wantErr:  true,
		},
		{
			name:     "rejects legacy nested limits map",
			settings: map[string]any{"limits": map[string]any{"global": map[string]any{"limit": 5, "window": "1m"}}},
			wantErr:  true,
		},
		{
			name:     "ignores unknown fields",
			settings: map[string]any{"limit": 5, "window": "1m", "actions": map[string]any{"type": "explode"}},
			wantErr:  false,
		},
	}
	p := New(nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPlugin_Execute_AllowsUnderLimit(t *testing.T) {
	p, _ := newTestPlugin(t)

	res, err := p.Execute(context.Background(), execInput(limitSettings(3, "1m"), consumerScope("c-1")))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, []string{"3"}, res.Headers["X-RateLimit-consumer-Limit"])
	assert.Equal(t, []string{"3"}, res.Headers["X-RateLimit-consumer-Remaining"])
}

func TestPlugin_Execute_RejectsOverLimit(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := map[string]any{"limit": 2, "window": "1m", "retry_after": "30"}

	for i := 0; i < 2; i++ {
		_, err := p.Execute(context.Background(), execInput(settings, consumerScope("c-1")))
		require.NoError(t, err, "request %d should pass", i)
	}

	_, err := p.Execute(context.Background(), execInput(settings, consumerScope("c-1")))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
	assert.Equal(t, []string{"30"}, pe.Headers["Retry-After"])
	assert.Equal(t, []string{"0"}, pe.Headers["X-RateLimit-consumer-Remaining"])
}

// A non-global policy must give each consumer an independent budget even when
// they share the same policy (same Config.ID).
func TestPlugin_Execute_ConsumerScopeIsolatesBudgets(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := limitSettings(1, "1m")

	_, err := p.Execute(context.Background(), execInput(settings, consumerScope("c-1")))
	require.NoError(t, err)
	// c-1 is now exhausted.
	_, err = p.Execute(context.Background(), execInput(settings, consumerScope("c-1")))
	require.Error(t, err)

	// c-2 shares the policy but must have its own budget.
	_, err = p.Execute(context.Background(), execInput(settings, consumerScope("c-2")))
	require.NoError(t, err, "a sibling consumer must not be affected by another consumer's usage")
}

// A global policy shares one counter across every consumer of the gateway.
func TestPlugin_Execute_GlobalScopeSharesBudget(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := limitSettings(1, "1m")

	res, err := p.Execute(context.Background(), execInput(settings, globalScope()))
	require.NoError(t, err)
	assert.Equal(t, []string{"1"}, res.Headers["X-RateLimit-global-Limit"])

	// The single global counter is now exhausted for the whole gateway.
	_, err = p.Execute(context.Background(), execInput(settings, globalScope()))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 429, pe.StatusCode)
}

// A non-global policy that reaches execution without a consumer id is a wiring
// bug; the plugin must surface it instead of falling back to a shared bucket.
func TestPlugin_Execute_ConsumerScopeRequiresConsumerID(t *testing.T) {
	p, _ := newTestPlugin(t)
	_, err := p.Execute(context.Background(), execInput(limitSettings(1, "1m"), appplugins.RuntimeScope{GatewayID: "gw-1"}))
	require.Error(t, err)
	_, ok := appplugins.AsPluginError(err)
	assert.False(t, ok, "a missing consumer id is an internal error, not a client rejection")
}

func TestPlugin_Execute_ObserveDoesNotReject(t *testing.T) {
	p, _ := newTestPlugin(t)
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeThrottle, policy.ModeObserve}, p.SupportedModes())

	settings := map[string]any{"limit": 1, "window": "1m", "retry_after": "30"}

	for i := 0; i < 5; i++ {
		in := execInput(settings, consumerScope("c-1"))
		in.Mode = policy.ModeObserve
		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err, "observe request %d should never be rejected", i)
		require.NotNil(t, res)
		assert.Equal(t, 200, res.StatusCode)
	}
}

func TestPlugin_Execute_ObserveReportsExceeded(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := limitSettings(1, "1m")

	first := execInput(settings, consumerScope("c-1"))
	first.Mode = policy.ModeObserve
	_, err := p.Execute(context.Background(), first)
	require.NoError(t, err)

	rt := trace.New("t", trace.Metadata{})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	second := execInput(settings, consumerScope("c-1"))
	second.Mode = policy.ModeObserve
	second.Event = metrics.NewEventContext(span)

	res, err := p.Execute(context.Background(), second)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)

	require.NotNil(t, span.Plugin)
	assert.Equal(t, "observe", span.Plugin.Decision)
	data, ok := span.Plugin.Extras.(RateLimiterData)
	require.True(t, ok, "extras should carry rate limiter data")
	assert.True(t, data.RateLimitExceeded, "must report the exceeded limit")
	assert.Equal(t, "consumer", data.ExceededType)
}

func TestPlugin_Execute_ThrottleDelaysButAllows(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := limitSettings(1, "200ms")

	for i := 0; i < 3; i++ {
		in := execInput(settings, consumerScope("c-1"))
		in.Mode = policy.ModeThrottle
		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err, "throttle request %d should not be rejected", i)
		require.NotNil(t, res)
		assert.Equal(t, 200, res.StatusCode)
	}
}

// With a group_by_header configured, the counter is sub-partitioned by header
// value within the policy scope: distinct values get independent budgets.
func TestPlugin_Execute_GroupByHeaderIsolatesByValue(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := headerSettings(1, "1m", "X-User-Id")

	u1 := map[string][]string{"X-User-Id": {"user-1"}}
	u2 := map[string][]string{"X-User-Id": {"user-2"}}

	_, err := p.Execute(context.Background(), execInputHdr(settings, consumerScope("c-1"), u1))
	require.NoError(t, err)
	// user-1's bucket is exhausted.
	_, err = p.Execute(context.Background(), execInputHdr(settings, consumerScope("c-1"), u1))
	require.Error(t, err)
	// user-2 has its own bucket within the same consumer.
	_, err = p.Execute(context.Background(), execInputHdr(settings, consumerScope("c-1"), u2))
	require.NoError(t, err, "a different header value must have an independent budget")
}

// Under a global policy the header partition is shared across consumers because
// the scope subject is the gateway, not the consumer.
func TestPlugin_Execute_GroupByHeaderSharedAcrossConsumersWhenGlobal(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := headerSettings(1, "1m", "X-User-Id")
	u1 := map[string][]string{"X-User-Id": {"user-1"}}

	// Same gateway, same header value, but two different consumers.
	scopeA := appplugins.RuntimeScope{GatewayID: "gw-1", ConsumerID: "c-1", Global: true}
	scopeB := appplugins.RuntimeScope{GatewayID: "gw-1", ConsumerID: "c-2", Global: true}

	_, err := p.Execute(context.Background(), execInputHdr(settings, scopeA, u1))
	require.NoError(t, err)
	_, err = p.Execute(context.Background(), execInputHdr(settings, scopeB, u1))
	require.Error(t, err, "global scope must share the header bucket across consumers of the gateway")
}

// When the header is configured but absent from the request, the counter falls
// back to the scope subject (here, the consumer).
func TestPlugin_Execute_GroupByHeaderFallsBackWhenAbsent(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := headerSettings(1, "1m", "X-User-Id")

	noHeader := map[string][]string{"X-Other": {"x"}}
	_, err := p.Execute(context.Background(), execInputHdr(settings, consumerScope("c-1"), noHeader))
	require.NoError(t, err)
	// The consumer-level fallback bucket is now exhausted.
	_, err = p.Execute(context.Background(), execInputHdr(settings, consumerScope("c-1"), noHeader))
	require.Error(t, err)
	// A request that does carry the header gets its own bucket.
	withHeader := map[string][]string{"X-User-Id": {"user-1"}}
	_, err = p.Execute(context.Background(), execInputHdr(settings, consumerScope("c-1"), withHeader))
	require.NoError(t, err)
}

// An empty header value is treated as if the header were absent: it falls back
// to the scope subject instead of creating an "empty value" bucket.
func TestPlugin_Execute_GroupByHeaderEmptyValueFallsBack(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := headerSettings(1, "1m", "X-User-Id")
	empty := map[string][]string{"X-User-Id": {""}}

	_, err := p.Execute(context.Background(), execInputHdr(settings, consumerScope("c-1"), empty))
	require.NoError(t, err)
	_, err = p.Execute(context.Background(), execInputHdr(settings, consumerScope("c-1"), empty))
	require.Error(t, err, "an empty header value must share the consumer fallback bucket")
}

func TestThrottleDelay(t *testing.T) {
	assert.Equal(t, time.Duration(0), throttleDelay(time.Minute, 0))
	assert.Equal(t, time.Duration(0), throttleDelay(0, 10))
	assert.Equal(t, 100*time.Millisecond, throttleDelay(time.Second, 10))
}

func TestPlugin_Execute_DefaultRetryAfter(t *testing.T) {
	p, _ := newTestPlugin(t)
	settings := limitSettings(1, "1m")

	_, err := p.Execute(context.Background(), execInput(settings, globalScope()))
	require.NoError(t, err)
	_, err = p.Execute(context.Background(), execInput(settings, globalScope()))
	require.Error(t, err)
	pe, _ := appplugins.AsPluginError(err)
	assert.Equal(t, []string{"60"}, pe.Headers["Retry-After"])
}
