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
	"errors"
	"sync"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/require"
)

// telemetrySample is one recorded label set. Recording the labels rather than an
// aggregate is what lets a test assert that nothing outside the enumerations
// ever reaches them.
type telemetrySample struct {
	kind    string
	outcome string
	era     string
}

// recordingSubscriptionsRecorder captures every label set and the running live
// delta, so both the outcome enumeration and the up/down accounting are
// observable without an OpenTelemetry reader.
type recordingSubscriptionsRecorder struct {
	mu      sync.Mutex
	samples []telemetrySample
	live    int64
}

func (r *recordingSubscriptionsRecorder) Record(_ context.Context, kind, outcome, era string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samples = append(r.samples, telemetrySample{kind: kind, outcome: outcome, era: era})
}

func (r *recordingSubscriptionsRecorder) Live(_ context.Context, delta int64, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live += delta
}

func (r *recordingSubscriptionsRecorder) recorded() []telemetrySample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]telemetrySample(nil), r.samples...)
}

func (r *recordingSubscriptionsRecorder) liveCount() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.live
}

// An emitted notification is the only sample that carries a kind, and the kind
// can only be one the lease honours, because the frame it names was rendered at
// open from the honoured subset alone.
func TestRunSubscriptionStream_RecordsBoundedEmissionLabels(t *testing.T) {
	t.Parallel()
	recorder := &recordingSubscriptionsRecorder{}
	timers, fake := newFakeTimers()
	policy := &scriptedPolicy{passes: []scriptedPass{
		{
			changed: []appmcp.NotificationKind{
				appmcp.NotificationToolsListChanged,
				appmcp.NotificationPromptsListChanged,
			},
			snapshot: appmcp.SurfaceSnapshot{Tools: "aaaaaaaaaaaa"},
		},
	}}
	spec := testReauthSpec(policy, timers)
	spec.recorder = recorder

	done := make(chan subscriptionOutcome, 1)
	go func() { done <- runSubscriptionStream(context.Background(), &recordingSink{}, spec) }()
	fake.reauth <- time.Now()
	awaitCondition(t, func() bool { return len(recorder.recorded()) == 1 })
	fake.deadline <- time.Now()
	require.Equal(t, subscriptionOutcomeDeadline, <-done)

	require.Equal(
		t,
		[]telemetrySample{{
			kind:    string(appmcp.NotificationToolsListChanged),
			outcome: trace.SubscriptionOutcomeEmitted,
			era:     trace.MCPProtocolEraModern,
		}},
		recorder.recorded(),
		"only an honoured kind is emittable, so only its emission is counted",
	)
	require.Zero(
		t,
		recorder.liveCount(),
		"the live counter belongs to the claim and the release, not to the loop",
	)
}

// An inconclusive pass emits nothing, so it must also count nothing: a telemetry
// sample per failed pass would make a dead upstream look like surface churn.
func TestRunSubscriptionStream_InconclusivePassRecordsNoEmission(t *testing.T) {
	t.Parallel()
	recorder := &recordingSubscriptionsRecorder{}
	timers, fake := newFakeTimers()
	policy := &scriptedPolicy{err: errors.New("upstream unavailable")}
	spec := testReauthSpec(policy, timers)
	spec.recorder = recorder

	done := make(chan subscriptionOutcome, 1)
	go func() { done <- runSubscriptionStream(context.Background(), &recordingSink{}, spec) }()
	fake.reauth <- time.Now()
	awaitScriptedCalls(t, policy, 1)
	fake.deadline <- time.Now()
	require.Equal(t, subscriptionOutcomeDeadline, <-done)

	require.Empty(t, recorder.recorded())
}

// A nil recorder is the ops-metrics-disabled build. The loop must behave
// identically, because the kill switch for telemetry is not a kill switch for
// the feature.
func TestRunSubscriptionStream_NilRecorderChangesNothing(t *testing.T) {
	t.Parallel()
	timers, fake := newFakeTimers()
	policy := &scriptedPolicy{passes: []scriptedPass{
		{changed: []appmcp.NotificationKind{appmcp.NotificationToolsListChanged}},
	}}
	spec := testReauthSpec(policy, timers)
	sink := &recordingSink{}

	done := make(chan subscriptionOutcome, 1)
	go func() { done <- runSubscriptionStream(context.Background(), sink, spec) }()
	fake.reauth <- time.Now()
	awaitCondition(t, func() bool { return len(sink.written()) == 2 })
	fake.deadline <- time.Now()
	require.Equal(t, subscriptionOutcomeDeadline, <-done)

	require.Equal(
		t,
		[]string{testAckFrame, testToolsChangedFrame, testTerminalFrame},
		sink.written(),
	)
}

// A recovered panic is deliberately outside the bounded outcome enumeration, so
// it must be dropped by the label filter rather than widen the label set. The
// operational route still reports it as a server error.
func TestSubscriptionOutcome_PanicIsOutsideTheBoundedEnumeration(t *testing.T) {
	t.Parallel()
	require.Empty(t, trace.BoundSubscriptionOutcome(string(subscriptionOutcomeFailed)))
	require.Equal(t, o11y.OutcomeServerError, subscriptionOutcomeFailed.opsOutcome())

	for _, outcome := range []subscriptionOutcome{
		subscriptionOutcomeOpened,
		subscriptionOutcomeRefused,
		subscriptionOutcomeEmitted,
		subscriptionOutcomeAcked,
		subscriptionOutcomeDeadline,
		subscriptionOutcomeShutdown,
		subscriptionOutcomeDisconnected,
		subscriptionOutcomeOversize,
		subscriptionOutcomeRevoked,
		subscriptionOutcomeDegraded,
	} {
		require.Equal(t, string(outcome), trace.BoundSubscriptionOutcome(string(outcome)))
	}
}

// Every kind the app layer can honour must survive the trace-layer filter, and
// nothing else may: the two enumerations are declared in different packages and
// would otherwise drift silently.
func TestBoundSubscriptionKind_MatchesTheHonourableKinds(t *testing.T) {
	t.Parallel()
	honoured := appmcp.NewHonouredSet(
		appmcp.NotificationToolsListChanged,
		appmcp.NotificationPromptsListChanged,
		appmcp.NotificationResourcesListChanged,
	)
	for _, kind := range honoured.Kinds() {
		require.Equal(t, string(kind), trace.BoundSubscriptionKind(string(kind)))
	}

	for _, raw := range []string{
		"", "resourceSubscriptions", "toolsListchanged", "doc://tenant/secret", "*",
	} {
		require.Empty(t, trace.BoundSubscriptionKind(raw), "unbounded kind %q must be dropped", raw)
	}
}

// The disabled build must hand back an untyped nil, since every call site guards
// on the interface itself rather than on a method result.
func TestNewSubscriptionsRecorder_NilWhenOpsMetricsDisabled(t *testing.T) {
	t.Parallel()
	require.Nil(t, NewSubscriptionsRecorder(false))
}
