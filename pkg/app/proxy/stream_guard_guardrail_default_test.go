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

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// RUN-1786: the guardrail plugins inspect a stream with no streaming key at
// all, fail open on a provider error, and never cut in observe. These run the
// real openai_moderation plugin and the real executor under the real stream
// guard against a stub provider, so each assertion is about what the client
// receives. The other two guardrails share the same pluginutil defaults and the
// same executor path.

const (
	provOK      = "ok"
	provFlagged = "flagged"
	provError   = "error"
)

// moderationStub answers the n-th call (1-based) with script[n-1], and with the
// last entry for every call after that.
func moderationStub(t *testing.T, script ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(calls.Add(1))
		kind := script[len(script)-1]
		if n <= len(script) {
			kind = script[n-1]
		}
		if kind == provError {
			http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
			return
		}
		flagged := kind == provFlagged
		w.Header().Set("Content-Type", "application/json")
		score := "0.01"
		if flagged {
			score = "0.95"
		}
		_, _ = w.Write([]byte(`{"id":"m","model":"omni-moderation-latest","results":[{"flagged":` +
			map[bool]string{true: "true", false: "false"}[flagged] +
			`,"categories":{"hate":` + map[bool]string{true: "true", false: "false"}[flagged] +
			`},"category_scores":{"hate":` + score + `}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// keyedModerationStub fails every call made with an api_key containing "bad"
// and answers clean to every other, so two policies of one plugin can sit on
// the same stream with one of them unable to inspect.
func keyedModerationStub(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var good, bad atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "bad") {
			bad.Add(1)
			http.Error(w, `{"error":"bad key"}`, http.StatusUnauthorized)
			return
		}
		good.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"m","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"hate":false},"category_scores":{"hate":0.01}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &good, &bad
}

func moderationPolicy(mode policy.Mode, streaming map[string]any) *policy.Policy {
	set := map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate": 0.7},
	}
	if streaming != nil {
		set["streaming"] = streaming
	}
	return &policy.Policy{
		ID:       ids.New[ids.PolicyKind](),
		Name:     openaimoderation.PluginName,
		Slug:     openaimoderation.PluginName,
		Enabled:  true,
		Parallel: true,
		Stages:   []policy.Stage{policy.StagePreResponse},
		Mode:     mode,
		Settings: set,
	}
}

// moderationGuard builds the guard the way the forwarder does: the options come
// from the plugin's own StreamSettings, so the defaults under test are the ones
// production gets.
func moderationGuard(t *testing.T, srvURL string, pol *policy.Policy, tweaks ...func(*streamGuardConfig)) (*streamGuard, bool) {
	t.Helper()
	return moderationGuardFor(t, srvURL, []*policy.Policy{pol}, tweaks...)
}

func moderationGuardFor(t *testing.T, srvURL string, pols []*policy.Policy, tweaks ...func(*streamGuardConfig)) (*streamGuard, bool) {
	t.Helper()
	plugin := openaimoderation.New(adapter.NewRegistry(), srvURL, 2*time.Second, nil)
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(plugin))
	// The forwarder asks the plan, which merges the options of every participant.
	joins, opts := appplugins.NewStagePlan(reg, pols, nil).StreamPlan(policy.StagePreResponse)
	if !joins {
		return nil, false
	}
	in := stageInputFixture()
	in.Policies = pols
	runner, ok := appplugins.NewExecutor(reg, nil).(segmentRunner)
	require.True(t, ok)
	cfg := streamGuardConfig{
		headChars: opts.HeadChars,
		onError:   streamOnError(opts.OnError),
		// Small blocks: the stub is instant, so the production cadence is not
		// what these tests are about.
		minChars:      1,
		maxHold:       time.Duration(opts.MaxHoldMS) * time.Millisecond,
		maxAccumBytes: opts.MaxAccumulatedBytes,
	}
	cfg.headChars = 1
	for _, tweak := range tweaks {
		tweak(&cfg)
	}
	return newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI, in, cfg, newGuardLogger()), true
}

type guardRun struct {
	text    string
	pe      *appplugins.PluginError
	stopped bool
}

func runModerationGuard(t *testing.T, g *streamGuard) guardRun {
	t.Helper()
	ctx, publish := appplugins.NewStreamSpanContext(trace.NewContext(context.Background(), trace.New("t", trace.Metadata{})))
	defer publish()
	out, pe := g.Run(ctx, invariantSource(t, g, textStreamLines("first block of text ", "second block of text ", "third block of text"), nil))
	if pe != nil {
		return guardRun{pe: pe, stopped: g.stopped}
	}
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	return guardRun{text: streamedText(t, adapter.FormatOpenAI, got), stopped: g.stopped}
}

const fullText = "first block of text second block of text third block of text"

func TestStreamGuard_GuardrailsInspectAStreamWithNoStreamingKey(t *testing.T) {
	t.Parallel()
	srv, calls := moderationStub(t, provFlagged)
	g, joins := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeEnforce, nil))
	require.True(t, joins, "a policy saved from the console carries no streaming key and must still inspect")

	run := runModerationGuard(t, g)

	require.NotNil(t, run.pe, "a flagged head is a clean 403 in enforce")
	assert.Equal(t, http.StatusForbidden, run.pe.StatusCode)
	assert.Positive(t, calls.Load())
}

func TestStreamGuard_GuardrailExplicitlyDisabledIsNotAParticipant(t *testing.T) {
	t.Parallel()
	srv, calls := moderationStub(t, provFlagged)
	_, joins := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeEnforce, map[string]any{"enabled": false}))

	assert.False(t, joins, "streaming.enabled: false is the opt-out")
	assert.Zero(t, calls.Load())
}

// Provider failures. The head and a later block take different paths in the
// guard (headFailure vs blockFailure), so each is pinned in each mode.
func TestStreamGuard_GuardrailProviderErrorFailsOpen(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		for name, script := range map[string][]string{
			"at the head":      {provError},
			"after the head":   {provOK, provError},
			"on every block":   {provError, provError, provError},
			"only the last":    {provOK, provOK, provError},
			"recovers midway":  {provOK, provError, provOK},
			"head ok then err": {provOK, provError, provError},
		} {
			t.Run(string(mode)+"/"+name, func(t *testing.T) {
				t.Parallel()
				srv, calls := moderationStub(t, script...)
				g, joins := moderationGuard(t, srv.URL, moderationPolicy(mode, nil))
				require.True(t, joins)

				run := runModerationGuard(t, g)

				require.Nil(t, run.pe, "a provider error must never be a status code")
				assert.False(t, run.stopped, "a provider error must never cut the stream")
				assert.Equal(t, fullText, run.text, "the whole response is released")
				assert.Positive(t, calls.Load(), "the provider was actually called")
			})
		}
	}
}

// An operator who asked for fail_closed still gets it in enforce. Observe never
// blocks, whatever the key says.
func TestStreamGuard_GuardrailExplicitFailClosedIsHonouredOnlyWhereItCanBlock(t *testing.T) {
	t.Parallel()
	closed := map[string]any{"on_error": "fail_closed"}

	t.Run("enforce at the head is a clean 403", func(t *testing.T) {
		t.Parallel()
		srv, _ := moderationStub(t, provError)
		g, _ := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeEnforce, closed))
		run := runModerationGuard(t, g)
		require.NotNil(t, run.pe)
		assert.Equal(t, http.StatusForbidden, run.pe.StatusCode)
	})
	t.Run("enforce after the head cuts", func(t *testing.T) {
		t.Parallel()
		srv, _ := moderationStub(t, provOK, provError)
		g, _ := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeEnforce, closed))
		run := runModerationGuard(t, g)
		assert.True(t, run.stopped)
		assert.NotEqual(t, fullText, run.text)
	})
	t.Run("observe at the head never blocks", func(t *testing.T) {
		t.Parallel()
		srv, _ := moderationStub(t, provError)
		g, _ := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeObserve, closed))
		run := runModerationGuard(t, g)
		require.Nil(t, run.pe)
		assert.False(t, run.stopped)
		assert.Equal(t, fullText, run.text)
	})
	t.Run("observe after the head never cuts", func(t *testing.T) {
		t.Parallel()
		srv, _ := moderationStub(t, provOK, provError)
		g, _ := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeObserve, closed))
		run := runModerationGuard(t, g)
		require.Nil(t, run.pe)
		assert.False(t, run.stopped)
		assert.Equal(t, fullText, run.text)
	})
}

// "block" from the provider in observe is a report, never a cut or a 403.
func TestStreamGuard_ObserveNeverBlocksOnAFlaggedVerdict(t *testing.T) {
	t.Parallel()
	for name, script := range map[string][]string{
		"flagged at the head":   {provFlagged},
		"flagged after":         {provOK, provFlagged},
		"flagged on every call": {provFlagged, provFlagged, provFlagged},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv, calls := moderationStub(t, script...)
			g, joins := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeObserve, nil))
			require.True(t, joins)

			run := runModerationGuard(t, g)

			require.Nil(t, run.pe)
			assert.False(t, run.stopped)
			assert.Equal(t, fullText, run.text)
			assert.Positive(t, calls.Load())
		})
	}
}

// Enforce still cuts a flagged block after the head: default-on must not have
// traded the verdict for the failure direction.
func TestStreamGuard_EnforceStillCutsAFlaggedBlockAfterTheHead(t *testing.T) {
	t.Parallel()
	srv, _ := moderationStub(t, provOK, provFlagged)
	g, _ := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeEnforce, nil))

	run := runModerationGuard(t, g)

	assert.True(t, run.stopped)
	assert.False(t, strings.Contains(run.text, "third"), "the flagged block is never released")
}

// spanDecisions runs the guard to the end and returns the decision of every
// plugin span of the stream, in span order.
func spanDecisions(t *testing.T, g *streamGuard) []string {
	t.Helper()
	rt := trace.New("t", trace.Metadata{})
	ctx, publish := appplugins.NewStreamSpanContext(trace.NewContext(context.Background(), rt))
	out, pe := g.Run(ctx, invariantSource(t, g, textStreamLines("first block of text ", "second block of text ", "third block of text"), nil))
	require.Nil(t, pe)
	_, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	publish()

	var decisions []string
	for _, span := range rt.Spans() {
		if span.Name == openaimoderation.PluginName {
			decisions = append(decisions, span.Plugin.Decision)
		}
	}
	return decisions
}

// spanDecisionsAnyOutcome is spanDecisions for a stream that may be refused at
// the head: the closing segment is published whether or not a status was sent.
func spanDecisionsAnyOutcome(t *testing.T, g *streamGuard) (*appplugins.PluginError, []string) {
	t.Helper()
	rt := trace.New("t", trace.Metadata{})
	ctx, publish := appplugins.NewStreamSpanContext(trace.NewContext(context.Background(), rt))
	out, pe := g.Run(ctx, invariantSource(t, g, textStreamLines("first block of text ", "second block of text ", "third block of text"), nil))
	if pe == nil {
		_, err := collectGuardOutput(t, g, out)
		require.NoError(t, err)
	}
	publish()
	var decisions []string
	for _, span := range rt.Spans() {
		if span.Name == openaimoderation.PluginName {
			decisions = append(decisions, span.Plugin.Decision)
		}
	}
	return pe, decisions
}

// The span of the policy records failed_open when a block went uninspected, in
// both modes, and the closing segment does not paper over it with "allowed".
// Every script ends on a success so that the failure is the only evidence: a
// stub that repeats its last answer would fail the later blocks too and hide an
// isolated failure.
func TestStreamGuard_GuardrailRecordsFailedOpenOnTheSpan(t *testing.T) {
	t.Parallel()
	// 25 bytes is smaller than the text of the second block, so every block
	// after the failure also degrades to a tail window (accumulation_cap).
	capped := func(c *streamGuardConfig) { c.maxAccumBytes = 25 }
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		for name, tc := range map[string]struct {
			script []string
			tweak  func(*streamGuardConfig)
		}{
			"isolated head failure":                 {[]string{provError, provOK}, nil},
			"isolated mid-stream failure":           {[]string{provOK, provError, provOK}, nil},
			"failure followed by a capped block":    {[]string{provOK, provError, provOK}, capped},
			"head failure followed by capped block": {[]string{provError, provOK, provOK}, capped},
		} {
			t.Run(string(mode)+"/"+name, func(t *testing.T) {
				t.Parallel()
				srv, _ := moderationStub(t, tc.script...)
				var tweaks []func(*streamGuardConfig)
				if tc.tweak != nil {
					tweaks = append(tweaks, tc.tweak)
				}
				g, _ := moderationGuard(t, srv.URL, moderationPolicy(mode, nil), tweaks...)

				assert.Equal(t, []string{"failed_open"}, spanDecisions(t, g))
			})
		}
	}
}

func TestStreamGuard_GuardrailCleanStreamStaysAllowed(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		srv, _ := moderationStub(t, provOK)
		g, _ := moderationGuard(t, srv.URL, moderationPolicy(mode, nil), func(c *streamGuardConfig) { c.maxAccumBytes = 25 })

		assert.Equal(t, []string{"allowed"}, spanDecisions(t, g), string(mode))
	}
}

// A failure is the failing policy's alone. The guard's degraded_reason is one
// value for the whole chain and is copied to every entry, so reading it labelled
// the policy with a good key as well.
func TestStreamGuard_GuardrailFailureIsLabelledOnTheFailingPolicyOnly(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			srv, _, _ := keyedModerationStub(t)
			good, bad := moderationPolicy(mode, nil), moderationPolicy(mode, nil)
			good.Settings["api_key"], bad.Settings["api_key"] = "good", "bad"
			good.Priority, bad.Priority = 1, 2
			g, joins := moderationGuardFor(t, srv.URL, []*policy.Policy{good, bad})
			require.True(t, joins)

			decisions := spanDecisions(t, g)

			assert.ElementsMatch(t, []string{"allowed", "failed_open"}, decisions)
		})
	}
}

// A cancelled stream is the client leaving, not the provider failing: no policy
// is labelled failed_open for it.
func TestStreamGuard_GuardrailCancellationIsNotAFailure(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			srv, _ := moderationStub(t, provOK)
			pol := moderationPolicy(mode, nil)
			plugin := openaimoderation.New(adapter.NewRegistry(), srv.URL, 2*time.Second, nil)
			reg := appplugins.NewRegistry()
			require.NoError(t, reg.Register(plugin))
			exec := appplugins.NewExecutor(reg, nil)
			runner, ok := exec.(interface {
				RunStreamSegment(context.Context, appplugins.StageInput, appplugins.StreamSegment) (*appplugins.SegmentOutcome, error)
			})
			require.True(t, ok)

			rt := trace.New("t", trace.Metadata{})
			ctx, cancel := context.WithCancel(trace.NewContext(context.Background(), rt))
			ctx, publish := appplugins.NewStreamSpanContext(ctx)
			in := stageInputFixture()
			in.Policies = []*policy.Policy{pol}
			cancel()
			_, _ = runner.RunStreamSegment(ctx, in, appplugins.StreamSegment{StreamID: "s", Seq: 1, Accumulated: "text", Text: "text"})
			_, _ = runner.RunStreamSegment(ctx, in, appplugins.StreamSegment{StreamID: "s", Seq: 2, Closing: true})
			publish()

			for _, span := range rt.Spans() {
				assert.NotEqual(t, "failed_open", span.Plugin.Decision)
			}
		})
	}
}

// A fail_closed cut is a cut: the failing policy's span says blocked, not
// failed_open, whether the client got a 403 at the head or a terminator later.
func TestStreamGuard_GuardrailFailClosedCutIsLabelledBlocked(t *testing.T) {
	t.Parallel()
	closed := map[string]any{"on_error": "fail_closed"}
	t.Run("head 403", func(t *testing.T) {
		t.Parallel()
		srv, _ := moderationStub(t, provError)
		g, _ := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeEnforce, closed))
		pe, decisions := spanDecisionsAnyOutcome(t, g)
		require.NotNil(t, pe)
		assert.Equal(t, http.StatusForbidden, pe.StatusCode)
		assert.Equal(t, []string{"block"}, decisions)
	})
	t.Run("cut after the head", func(t *testing.T) {
		t.Parallel()
		srv, _ := moderationStub(t, provOK, provError)
		g, _ := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeEnforce, closed))
		pe, decisions := spanDecisionsAnyOutcome(t, g)
		require.Nil(t, pe)
		assert.Equal(t, []string{"block"}, decisions)
	})
}

// One policy asked for fail_closed; another, on its default, has an outage. The
// stream's single on_error is fail_closed because of the first, and must not
// cut on the second's behalf: its failure is its own and fails open. The
// chain order is irrelevant, so both are run.
func TestStreamGuard_GuardrailOutageOfADefaultPolicyDoesNotCutOnAStrictOnesBehalf(t *testing.T) {
	t.Parallel()
	for name, prios := range map[string][2]int{"strict first": {1, 2}, "flaky first": {2, 1}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv, good, bad := keyedModerationStub(t)
			strict := moderationPolicy(policy.ModeEnforce, map[string]any{"on_error": "fail_closed"})
			flaky := moderationPolicy(policy.ModeEnforce, nil)
			strict.Settings["api_key"], flaky.Settings["api_key"] = "good", "bad"
			strict.Priority, flaky.Priority = prios[0], prios[1]
			g, joins := moderationGuardFor(t, srv.URL, []*policy.Policy{strict, flaky})
			require.True(t, joins)
			require.Equal(t, streamFailClosed, g.cfg.onError, "the merged stream option is what is under test")

			pe, decisions := spanDecisionsAnyOutcome(t, g)

			require.Nil(t, pe)
			assert.False(t, g.stopped, "an outage of a fail_open policy must not cut the stream")
			assert.ElementsMatch(t, []string{"allowed", "failed_open"}, decisions)
			// The strict policy inspected every block, including the final one,
			// whichever sorts first.
			assert.Greater(t, good.Load(), bad.Load(), "the healthy policy is called on every block, past the failing one's retirement")
			assert.LessOrEqual(t, bad.Load(), int32(3), "the failing policy is retired after three blocks in a row")
		})
	}
}

type runSpan struct {
	decision string
	data     openaimoderation.ModerationData
}

// runManyBlocks drives a stream of n blocks and returns the plugin spans.
func runManyBlocks(t *testing.T, g *streamGuard, n int) []runSpan {
	t.Helper()
	chunks := make([]string, n)
	for i := range chunks {
		chunks[i] = "block of text number " + string(rune('a'+i)) + " "
	}
	rt := trace.New("t", trace.Metadata{})
	ctx, publish := appplugins.NewStreamSpanContext(trace.NewContext(context.Background(), rt))
	out, pe := g.Run(ctx, invariantSource(t, g, textStreamLines(chunks...), nil))
	require.Nil(t, pe)
	_, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	publish()
	var spans []runSpan
	for _, span := range rt.Spans() {
		if span.Name != openaimoderation.PluginName {
			continue
		}
		attrs := span.PluginAttrsCopy()
		data, _ := attrs.Extras.(openaimoderation.ModerationData)
		spans = append(spans, runSpan{decision: attrs.Decision, data: data})
	}
	return spans
}

// A provider that keeps failing is called a bounded number of times for ITS
// policy, and only that policy: the healthy policy beside it inspects every
// block. Absorbing the failure per entry hides it from the guard, which would
// otherwise retire the whole loop, so the retirement has to live per entry.
func TestStreamGuard_GuardrailFailingProviderIsRetiredPerEntry(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			srv, good, bad := keyedModerationStub(t)
			healthy, flaky := moderationPolicy(policy.ModeEnforce, nil), moderationPolicy(mode, nil)
			healthy.Settings["api_key"], flaky.Settings["api_key"] = "good", "bad"
			healthy.Priority, flaky.Priority = 1, 2
			g, joins := moderationGuardFor(t, srv.URL, []*policy.Policy{healthy, flaky})
			require.True(t, joins)

			spans := runManyBlocks(t, g, 8)

			assert.LessOrEqual(t, bad.Load(), int32(3), "the failing provider is called at most three times")
			assert.GreaterOrEqual(t, good.Load(), int32(8), "the healthy policy still inspects every block")
			require.Len(t, spans, 2)
			var failed []runSpan
			for _, sp := range spans {
				if sp.decision == "failed_open" {
					failed = append(failed, sp)
				}
			}
			require.Len(t, failed, 1, "only the failing policy is labelled")
			require.NotNil(t, failed[0].data.Streaming)
			assert.Equal(t, appplugins.StreamFallbackEntryRetired, failed[0].data.Streaming.FallbackReason)
		})
	}
}

// A failed call is not a call that came back: guard_calls is the blocks that
// got every verdict, so it stays short of evals_total by the failures the chain
// absorbed.
func TestStreamGuard_GuardrailGuardCallsExcludeAbsorbedFailures(t *testing.T) {
	t.Parallel()
	srv, _ := moderationStub(t, provOK, provError, provOK)
	g, _ := moderationGuard(t, srv.URL, moderationPolicy(policy.ModeEnforce, nil))

	spans := runManyBlocks(t, g, 4)

	require.Len(t, spans, 1)
	require.NotNil(t, spans[0].data.Streaming)
	st := spans[0].data.Streaming
	assert.Equal(t, st.EvalsTotal-1, st.GuardCalls, "one block failed, so one eval is not a guard call")
}
