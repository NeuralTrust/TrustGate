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

package ratelimit

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const parallelKeyOfGlobal = "ratelimit:parallel:plugin-1:global:gw-1"

type fakeTimers struct {
	mu      sync.Mutex
	fns     []func()
	stopped []bool
}

func (f *fakeTimers) after(_ time.Duration, fn func()) func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fns = append(f.fns, fn)
	f.stopped = append(f.stopped, false)
	idx := len(f.fns) - 1
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.stopped[idx] = true
	}
}

func (f *fakeTimers) fireLast(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	require.NotEmpty(t, f.fns)
	fn := f.fns[len(f.fns)-1]
	f.stopped[len(f.fns)-1] = true
	f.mu.Unlock()
	fn()
}

func (f *fakeTimers) liveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.stopped {
		if !s {
			n++
		}
	}
	return n
}

type commandLog struct {
	mu            sync.Mutex
	names         []string
	failEval      error
	failAfterEval error
	evalDeadline  bool
}

func (c *commandLog) evalHadDeadline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evalDeadline
}

func (c *commandLog) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}

func (c *commandLog) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c.record(cmd.Name())
		if strings.HasPrefix(cmd.Name(), "eval") {
			if _, ok := ctx.Deadline(); ok {
				c.mu.Lock()
				c.evalDeadline = true
				c.mu.Unlock()
			}
		}
		if c.failEval != nil && strings.HasPrefix(cmd.Name(), "eval") {
			return c.failEval
		}
		err := next(ctx, cmd)
		if c.failAfterEval != nil && cmd.Name() == "eval" && err == nil {
			return c.failAfterEval
		}
		return err
	}
}

func (c *commandLog) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			c.record(cmd.Name())
		}
		return next(ctx, cmds)
	}
}

func (c *commandLog) record(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.names = append(c.names, name)
}

func (c *commandLog) has(prefix string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.names {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

func (c *commandLog) hasExact(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.names {
		if n == name {
			return true
		}
	}
	return false
}

type parallelEnv struct {
	p      *Plugin
	mr     *miniredis.Miniredis
	now    *time.Time
	timers *fakeTimers
	cmds   *commandLog
}

func newParallelEnv(t *testing.T) *parallelEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	env := &parallelEnv{mr: mr, now: new(time.Time), timers: &fakeTimers{}, cmds: &commandLog{}}
	*env.now = time.Unix(1_700_000_000, 0)
	rdb.AddHook(env.cmds)
	seq := 0
	env.p = New(rdb,
		WithClock(func() time.Time { return *env.now }),
		WithIDGenerator(func() string { seq++; return "req-" + string(rune('a'+seq)) }),
	)
	env.p.after = env.timers.after
	env.p.spawn = func(f func()) { f() }
	return env
}

func parallelSettings(maxParallel int, extra map[string]any) map[string]any {
	s := limitSettings(1000, "1m")
	s["max_parallel"] = maxParallel
	for k, v := range extra {
		s[k] = v
	}
	return s
}

func (e *parallelEnv) start(settings map[string]any, scope appplugins.RuntimeScope, mode policy.Mode) (*appplugins.RequestDone, *appplugins.Result, error) {
	done := appplugins.NewRequestDone()
	in := execInput(settings, scope)
	in.Mode = mode
	res, err := e.p.Execute(done.Bind(context.Background()), in)
	return done, res, err
}

func (e *parallelEnv) inFlight(key string) int {
	if !e.mr.Exists(key) {
		return 0
	}
	members, err := e.mr.ZMembers(key)
	if err != nil {
		return 0
	}
	return len(members)
}

func requirePluginError(t *testing.T, err error) *appplugins.PluginError {
	t.Helper()
	var perr *appplugins.PluginError
	require.ErrorAs(t, err, &perr)
	return perr
}

func requireRefused(t *testing.T, err error) {
	t.Helper()
	var perr *appplugins.PluginError
	require.ErrorAs(t, err, &perr)
}

func TestPlugin_Parallel_AcquireOverLimitAndRelease(t *testing.T) {
	tests := []struct {
		name string
		mode policy.Mode
	}{
		{"enforce", policy.ModeEnforce},
		{"throttle rejects like enforce", policy.ModeThrottle},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newParallelEnv(t)
			settings := parallelSettings(2, nil)

			first, _, err := env.start(settings, globalScope(), tt.mode)
			require.NoError(t, err)
			_, _, err = env.start(settings, globalScope(), tt.mode)
			require.NoError(t, err)
			assert.Equal(t, 2, env.inFlight(parallelKeyOfGlobal))

			_, _, err = env.start(settings, globalScope(), tt.mode)
			perr := requirePluginError(t, err)
			assert.Equal(t, http.StatusTooManyRequests, perr.StatusCode)
			assert.Empty(t, perr.Headers["Retry-After"], "a slot has no known time of return")
			assert.Empty(t, perr.Headers)
			assert.Equal(t, 2, env.inFlight(parallelKeyOfGlobal), "a refused request holds no slot")

			first.Run()
			assert.Equal(t, 1, env.inFlight(parallelKeyOfGlobal))
			_, _, err = env.start(settings, globalScope(), tt.mode)
			require.NoError(t, err, "the freed slot is reusable")
		})
	}
}

func TestPlugin_Parallel_ReleaseIsExactlyOnce(t *testing.T) {
	env := newParallelEnv(t)
	settings := parallelSettings(2, nil)
	a, _, err := env.start(settings, globalScope(), policy.ModeEnforce)
	require.NoError(t, err)
	_, _, err = env.start(settings, globalScope(), policy.ModeEnforce)
	require.NoError(t, err)

	a.Run()
	a.Run()

	assert.Equal(t, 1, env.inFlight(parallelKeyOfGlobal), "a second release must not free another request's slot")
	assert.Zero(t, env.timers.liveCount()-1, "the released lease stopped its heartbeat")
}

func TestPlugin_Parallel_RequestAlreadyEndedReleasesAtOnce(t *testing.T) {
	env := newParallelEnv(t)
	done := appplugins.NewRequestDone()
	done.Run()
	in := execInput(parallelSettings(1, nil), globalScope())

	_, err := env.p.Execute(done.Bind(context.Background()), in)

	require.NoError(t, err)
	assert.Zero(t, env.inFlight(parallelKeyOfGlobal))
}

func TestPlugin_Parallel_CrashedPodLeaseExpires(t *testing.T) {
	env := newParallelEnv(t)
	settings := parallelSettings(1, nil)
	_, _, err := env.start(settings, globalScope(), policy.ModeEnforce)
	require.NoError(t, err)

	_, _, err = env.start(settings, globalScope(), policy.ModeEnforce)
	requireRefused(t, err)

	*env.now = env.now.Add(leaseTTL + time.Second)
	_, _, err = env.start(settings, globalScope(), policy.ModeEnforce)
	require.NoError(t, err, "the lease of a pod that never released has expired")
	assert.Equal(t, 1, env.inFlight(parallelKeyOfGlobal), "the expired lease was purged")
}

func TestPlugin_Parallel_HeartbeatKeepsALongStreamAlive(t *testing.T) {
	env := newParallelEnv(t)
	settings := parallelSettings(1, nil)
	stream, _, err := env.start(settings, globalScope(), policy.ModeEnforce)
	require.NoError(t, err)

	*env.now = env.now.Add(heartbeatEvery)
	env.timers.fireLast(t)
	*env.now = env.now.Add(leaseTTL - time.Second)
	env.timers.fireLast(t)
	// Past the first lease's own TTL, still held because it was refreshed.
	_, _, err = env.start(settings, globalScope(), policy.ModeEnforce)
	requireRefused(t, err)

	stream.Run()
	assert.Zero(t, env.inFlight(parallelKeyOfGlobal))
	before := env.timers.liveCount()
	env.timers.fireLast(t)
	assert.Zero(t, env.inFlight(parallelKeyOfGlobal), "a stale heartbeat must not resurrect a released lease")
	assert.Equal(t, before, env.timers.liveCount(), "no heartbeat is rescheduled after release")
}

func TestPlugin_Parallel_HeartbeatStopsAtMaxLeaseLife(t *testing.T) {
	env := newParallelEnv(t)
	_, _, err := env.start(parallelSettings(1, nil), globalScope(), policy.ModeEnforce)
	require.NoError(t, err)
	before := len(env.timers.fns)

	*env.now = env.now.Add(maxLeaseLife)
	env.timers.fireLast(t)

	assert.Len(t, env.timers.fns, before, "a lease past its maximum life is no longer refreshed")
}

func TestPlugin_Parallel_KeyExpiresWhenIdle(t *testing.T) {
	env := newParallelEnv(t)
	_, _, err := env.start(parallelSettings(1, nil), globalScope(), policy.ModeEnforce)
	require.NoError(t, err)

	assert.Equal(t, leaseTTL, env.mr.TTL(parallelKeyOfGlobal))
}

func TestPlugin_Parallel_FollowsLimitPer(t *testing.T) {
	appScope := func(app string) appplugins.RuntimeScope {
		s := globalScope()
		s.ConsumerID = app
		return s
	}
	t.Run("each application has its own set under the request counter's suffix", func(t *testing.T) {
		env := newParallelEnv(t)
		settings := parallelSettings(1, map[string]any{"limit_per": "application"})

		_, _, err := env.start(settings, appScope("app-1"), policy.ModeEnforce)
		require.NoError(t, err)
		_, _, err = env.start(settings, appScope("app-2"), policy.ModeEnforce)
		require.NoError(t, err)
		_, _, err = env.start(settings, appScope("app-1"), policy.ModeEnforce)
		requireRefused(t, err)

		assert.Equal(t, 1, env.inFlight("ratelimit:parallel:plugin-1:global:gw-1:app:app-1"))
		assert.Equal(t, 1, env.inFlight("ratelimit:parallel:plugin-1:global:gw-1:app:app-2"))
		assert.True(t, env.mr.Exists("ratelimit:plugin-1:global:gw-1:app:app-1"), "the request counter keeps its own namespace")
	})
	t.Run("a header partition gets its own set", func(t *testing.T) {
		env := newParallelEnv(t)
		settings := parallelSettings(1, map[string]any{"group_by_header": "X-Tenant"})
		run := func(tenant string) error {
			in := execInputHdr(settings, globalScope(), map[string][]string{"X-Tenant": {tenant}})
			_, err := env.p.Execute(appplugins.NewRequestDone().Bind(context.Background()), in)
			return err
		}

		require.NoError(t, run("a"))
		require.NoError(t, run("b"))
		requireRefused(t, run("a"))
		assert.Equal(t, 1, env.inFlight(parallelKeyOfGlobal+":hdr:a"))
	})
	t.Run("a request the policy does not apply to takes no slot", func(t *testing.T) {
		env := newParallelEnv(t)
		settings := parallelSettings(1, map[string]any{"limit_per": "application", "applies_to": "selected", "selected": []string{"app-2"}})

		for i := 0; i < 3; i++ {
			_, _, err := env.start(settings, appScope("app-1"), policy.ModeEnforce)
			require.NoError(t, err)
		}

		assert.Empty(t, env.mr.Keys())
		assert.False(t, env.cmds.has("eval"))
	})
}

func TestPlugin_Parallel_ObserveReportsAndDoesNotBlock(t *testing.T) {
	env := newParallelEnv(t)
	settings := parallelSettings(1, nil)

	first, _, err := env.start(settings, globalScope(), policy.ModeObserve)
	require.NoError(t, err)
	span := trace.New("t", trace.Metadata{}).StartSpan(trace.SpanPlugin, PluginName)
	done := appplugins.NewRequestDone()
	in := execInput(settings, globalScope())
	in.Mode = policy.ModeObserve
	in.Event = metrics.NewEventContext(span)
	res, err := env.p.Execute(done.Bind(context.Background()), in)
	require.NoError(t, err)
	second := done

	data, ok := span.Plugin.Extras.(RateLimiterData)
	require.True(t, ok)
	assert.True(t, data.ParallelExceeded)
	assert.EqualValues(t, 2, data.CurrentParallel)
	assert.Equal(t, 1, data.MaxParallel)
	assert.Equal(t, "observe", span.Plugin.Decision)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, 2, env.inFlight(parallelKeyOfGlobal), "observe keeps the in-flight count true")
	first.Run()
	second.Run()
	assert.Zero(t, env.inFlight(parallelKeyOfGlobal))
}

func TestPlugin_Parallel_UnsetTouchesNoSlotState(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
	}{
		{"absent", limitSettings(5, "1m")},
		{"zero", parallelSettings(0, nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newParallelEnv(t)

			_, _, err := env.start(tt.settings, globalScope(), policy.ModeEnforce)
			require.NoError(t, err)

			assert.False(t, env.cmds.has("eval"), "no script is run")
			assert.False(t, env.cmds.hasExact("zrem"))
			assert.Equal(t, []string{"ratelimit:plugin-1:global:gw-1"}, env.mr.Keys())
			assert.Empty(t, env.timers.fns)
		})
	}
}

func TestPlugin_Parallel_CounterErrorFailsOpen(t *testing.T) {
	env := newParallelEnv(t)
	env.cmds.failEval = errors.New("redis down")

	span := trace.New("t", trace.Metadata{}).StartSpan(trace.SpanPlugin, PluginName)
	in := execInput(parallelSettings(1, nil), globalScope())
	in.Event = metrics.NewEventContext(span)

	res, err := env.p.Execute(appplugins.NewRequestDone().Bind(context.Background()), in)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Len(t, env.timers.fns, 1, "the heartbeat is armed in case the script ran before the reply was lost")
	assert.Equal(t, "failed_open", span.Plugin.Decision)
	data, ok := span.Plugin.Extras.(RateLimiterData)
	require.True(t, ok)
	assert.Equal(t, "acquire", data.FailureDetail)
	assert.Equal(t, string(appplugins.FailureCounterUnavailable), data.FailureReason)
}

func TestPlugin_Parallel_LostAcquireReplyDoesNotLeakTheSlot(t *testing.T) {
	env := newParallelEnv(t)
	env.cmds.failAfterEval = errors.New("reply lost")

	done, res, err := env.start(parallelSettings(1, nil), globalScope(), policy.ModeEnforce)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, "the request failed open")
	require.Equal(t, 1, env.inFlight(parallelKeyOfGlobal), "the script did add the member")

	require.Equal(t, 1, env.timers.liveCount(), "the admitted request keeps its lease alive")
	*env.now = env.now.Add(leaseTTL + time.Second)
	env.timers.fireLast(t)
	score, zerr := env.mr.ZScore(parallelKeyOfGlobal, "req-b")
	require.NoError(t, zerr)
	assert.Greater(t, score, float64(env.now.UnixMilli()), "the heartbeat refreshed the lease")

	done.Run()

	assert.Zero(t, env.inFlight(parallelKeyOfGlobal), "the end of the request frees it")
	assert.Zero(t, env.timers.liveCount())
}

func TestPlugin_Parallel_StalledAcquireFailsOpen(t *testing.T) {
	env := newParallelEnv(t)
	env.cmds.failEval = context.DeadlineExceeded

	done, res, err := env.start(parallelSettings(1, nil), globalScope(), policy.ModeEnforce)
	require.NoError(t, err, "a deadline of the acquire's own is not the caller leaving")
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.True(t, env.cmds.evalHadDeadline(), "the acquire runs under its own deadline")
	done.Run()
}

func TestPlugin_Parallel_HeartbeatRacingRelease(t *testing.T) {
	for i := 0; i < 200; i++ {
		env := newParallelEnv(t)
		var removes atomic.Int32
		env.p.spawn = func(f func()) { removes.Add(1); f() }
		done, _, err := env.start(parallelSettings(1, nil), globalScope(), policy.ModeEnforce)
		require.NoError(t, err)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); env.timers.fireLast(t) }()
		go func() { defer wg.Done(); done.Run() }()
		wg.Wait()

		require.Zero(t, env.timers.liveCount(), "no heartbeat outlives the release")
		require.EqualValues(t, 1, removes.Load())
		require.Zero(t, env.inFlight(parallelKeyOfGlobal))
	}
}

func TestPlugin_Parallel_ReleaseDoesNotBlockTheResponse(t *testing.T) {
	env := newParallelEnv(t)
	var pending []func()
	env.p.spawn = func(f func()) { pending = append(pending, f) }
	done, _, err := env.start(parallelSettings(1, nil), globalScope(), policy.ModeEnforce)
	require.NoError(t, err)

	done.Run()

	require.Len(t, pending, 1)
	assert.Equal(t, 1, env.inFlight(parallelKeyOfGlobal), "the ZREM has not run on the caller's path")
	assert.Zero(t, env.timers.liveCount(), "the heartbeat is already stopped")
	pending[0]()
	assert.Zero(t, env.inFlight(parallelKeyOfGlobal))
}

func TestPlugin_Parallel_RefusedRequestsAndTheRequestCounter(t *testing.T) {
	const requestKey = "ratelimit:plugin-1:global:gw-1"
	t.Run("a parallel 429 is not recorded as a request", func(t *testing.T) {
		env := newParallelEnv(t)
		settings := parallelSettings(1, nil)
		_, _, err := env.start(settings, globalScope(), policy.ModeEnforce)
		require.NoError(t, err)

		_, _, err = env.start(settings, globalScope(), policy.ModeEnforce)
		requireRefused(t, err)

		members, zerr := env.mr.ZMembers(requestKey)
		require.NoError(t, zerr)
		assert.Len(t, members, 1)
	})
	t.Run("a request-limit 429 takes no slot", func(t *testing.T) {
		env := newParallelEnv(t)
		settings := limitSettings(1, "1m")
		settings["max_parallel"] = 5
		_, _, err := env.start(settings, globalScope(), policy.ModeEnforce)
		require.NoError(t, err)

		_, _, err = env.start(settings, globalScope(), policy.ModeEnforce)
		requireRefused(t, err)

		assert.Equal(t, 1, env.inFlight(parallelKeyOfGlobal), "only the admitted request holds a slot")
	})
}

func TestPlugin_Parallel_WithoutEndHookIsSkipped(t *testing.T) {
	env := newParallelEnv(t)
	settings := parallelSettings(1, nil)

	for i := 0; i < 2; i++ {
		_, err := env.p.Execute(context.Background(), execInput(settings, globalScope()))
		require.NoError(t, err)
	}

	assert.False(t, env.cmds.has("eval"), "nothing could free the slot, so none is taken")
}

func TestPlugin_ValidateConfig_MaxParallel(t *testing.T) {
	tests := []struct {
		name    string
		value   any
		wantErr bool
	}{
		{"positive", 3, false},
		{"zero is no limit", 0, false},
		{"negative", -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := limitSettings(5, "1m")
			s["max_parallel"] = tt.value
			err := New(nil).ValidateConfig(s)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
	assert.NoError(t, New(nil).ValidateConfig(limitSettings(5, "1m")), "max_parallel is optional")
}
