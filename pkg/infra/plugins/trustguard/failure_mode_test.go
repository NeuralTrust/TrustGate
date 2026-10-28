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

package trustguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func withFailureMode(set map[string]any, mode string) map[string]any {
	if mode != "" {
		set["failure_mode"] = mode
	}
	return set
}

func TestParseConfigFailureMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		value   any
		set     bool
		want    string
		wantErr bool
	}{
		{name: "absent defaults to open", want: failureModeOpen},
		{name: "empty defaults to open", value: "", set: true, want: failureModeOpen},
		{name: "open accepted", value: "open", set: true, want: failureModeOpen},
		{name: "closed accepted", value: "closed", set: true, want: failureModeClosed},
		{name: "other value rejected", value: "fail_closed", set: true, wantErr: true},
		{name: "case matters", value: "Closed", set: true, wantErr: true},
		{name: "non string rejected", value: true, set: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set := map[string]any{"collector_id": testCollectorID}
			if tc.set {
				set["failure_mode"] = tc.value
			}
			cfg, err := parseConfig(set)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.FailureMode)
			assert.Equal(t, tc.want == failureModeClosed, cfg.failClosed())
		})
	}
}

// failure_mode is a live key: the plugin must not declare it retired, or the
// policy creator and updater would strip it on every write.
func TestFailureModeIsNotRetired(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://guard.local", time.Second, "id", "secret", nil)
	assert.NotContains(t, p.RetiredSettings(), "failure_mode")
	assert.Contains(t, p.RetiredSettings(), "on_error", "the retired keys stay retired")
	stripped := appplugins.StripRetiredSettings(singleRegistry{p: p}, PluginName, map[string]any{
		"collector_id": testCollectorID, "failure_mode": "closed", "on_error": "fail_closed",
	})
	assert.Equal(t, map[string]any{"collector_id": testCollectorID, "failure_mode": "closed"}, stripped)
}

type singleRegistry struct {
	appplugins.Registry
	p *Plugin
}

func (r singleRegistry) Get(string) (appplugins.Plugin, bool) { return r.p, true }

// headerSpy records X-Failure-Mode on every evaluate call before the fake
// TrustGuard answers it.
type headerSpy struct {
	mu    sync.Mutex
	modes []string
	next  http.Handler
}

func (h *headerSpy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == evaluatePath {
		h.mu.Lock()
		h.modes = append(h.modes, r.Header.Get(failureModeHeader))
		h.mu.Unlock()
	}
	h.next.ServeHTTP(w, r)
}

func (h *headerSpy) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.modes...)
}

func spyOn(t *testing.T, next http.Handler) (*httptest.Server, *headerSpy) {
	t.Helper()
	spy := &headerSpy{next: next}
	srv := httptest.NewServer(spy)
	t.Cleanup(srv.Close)
	return srv, spy
}

func TestGuardSendsFailureModeHeader(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, mode, want string }{
		{"unset defaults to open", "", "open"},
		{"open", "open", "open"},
		{"closed", "closed", "closed"},
	} {
		t.Run("client "+tc.name, func(t *testing.T) {
			t.Parallel()
			got := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got <- r.Header.Get(failureModeHeader)
				_, _ = w.Write([]byte(`{"status":"allow"}`))
			}))
			t.Cleanup(srv.Close)
			body := sampleRequest()
			body.FailureMode = tc.mode
			_, err := newTestClient(t, time.Second).Guard(context.Background(), srv.URL, "k", "", body, false)
			require.NoError(t, err)
			assert.Equal(t, tc.want, <-got)
		})
		t.Run("buffered "+tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			srv, spy := spyOn(t, f.handler())
			p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
			_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce,
				withFailureMode(settings(""), tc.mode), requestContext(), nil))
			require.NoError(t, err)
			assert.Equal(t, []string{tc.want}, spy.seen())
		})
		t.Run("streamed "+tc.name, func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
			g.release = make(chan struct{})
			t.Cleanup(func() { close(g.release) })
			srv, spy := spyOn(t, g.handler())
			p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
			set := withFailureMode(streamingSettings(nil), tc.mode)
			_, err := p.InspectSegment(segmentTraceContext(), execInput(policy.StagePreResponse, policy.ModeEnforce, set, segmentRequest(), nil),
				appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
			require.NoError(t, err)
			assert.Equal(t, []string{tc.want}, spy.seen())
		})
	}
}

// failureLeg is one way TrustGuard can fail to evaluate. Every one is an
// availability failure: nothing about the request caused it.
type failureLeg struct {
	name   string
	reason string
	// plugin builds the plugin under test and returns it with the guard's URL.
	plugin func(t *testing.T) *Plugin
}

func availabilityLegs() []failureLeg {
	return []failureLeg{
		{"unreachable", failureReasonTransport, func(t *testing.T) *Plugin {
			srv := httptest.NewServer(http.NotFoundHandler())
			url := srv.URL
			srv.Close()
			return newTestPlugin(t, adapter.NewRegistry(), url)
		}},
		{"5xx", failureReasonTransport, func(t *testing.T) *Plugin {
			return newTestPlugin(t, adapter.NewRegistry(), newServer(t, &fakeGuard{status: http.StatusInternalServerError}).URL)
		}},
		{"timeout", failureReasonTimeout, func(t *testing.T) *Plugin {
			f := &fakeGuard{response: GuardResponse{Status: statusAllow}, delay: 2 * time.Second}
			return New(adapter.NewRegistry(), newServer(t, f).URL, 150*time.Millisecond, "test-client", "test-secret", nil,
				withBaseTransport(testTransport(t)))
		}},
	}
}

func TestExecuteFailureModeOnAvailabilityFailures(t *testing.T) {
	t.Parallel()
	for _, leg := range availabilityLegs() {
		for _, tc := range []struct {
			mode     string
			policy   policy.Mode
			refused  bool
			decision string
		}{
			{"", policy.ModeEnforce, false, decisionFailedOpen},
			{"open", policy.ModeEnforce, false, decisionFailedOpen},
			{"closed", policy.ModeEnforce, true, decisionFailedClosed},
			{"closed", policy.ModeObserve, false, decisionFailedOpen},
		} {
			t.Run(leg.name+"/"+tc.mode+"/"+string(tc.policy), func(t *testing.T) {
				t.Parallel()
				p := leg.plugin(t)
				event, span := newEvent()
				res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, tc.policy,
					withFailureMode(settings(""), tc.mode), requestContext(), nil, event))
				if tc.refused {
					pe, ok := appplugins.AsPluginError(err)
					require.True(t, ok, "want a *PluginError, got %v", err)
					assert.Equal(t, http.StatusForbidden, pe.StatusCode)
					assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
					assert.Nil(t, res)
				} else {
					require.NoError(t, err)
					require.NotNil(t, res)
					assert.Equal(t, http.StatusOK, res.StatusCode)
					assert.False(t, res.StopUpstream)
				}
				extras, ok := span.PluginAttrsCopy().Extras.(guardData)
				require.True(t, ok)
				assert.Equal(t, tc.decision, extras.Decision)
				assert.Equal(t, leg.reason, extras.FailureReason)
				assert.Equal(t, tc.refused, extras.FailedClosed)
				assert.Equal(t, !tc.refused, extras.FailedOpen)
				assert.Equal(t, "availability", extras.FailureClass, "the class is the real one in every mode")
				assert.Equal(t, tc.mode == "closed", extras.FailureMode == "closed")
			})
		}
	}
}

// A 413 is the request's own size and is refused in a blocking mode whatever
// failure_mode says.
func TestExecutePayloadTooLargeIsTheSameInBothModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"", "open", "closed"} {
		for _, pm := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(mode+"/"+string(pm), func(t *testing.T) {
				t.Parallel()
				p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, &fakeGuard{status: http.StatusRequestEntityTooLarge}).URL)
				event, span := newEvent()
				res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, pm,
					withFailureMode(settings(""), mode), requestContext(), nil, event))
				extras, ok := span.PluginAttrsCopy().Extras.(guardData)
				require.True(t, ok)
				assert.Equal(t, failureReasonPayloadTooLarge, extras.FailureReason)
				assert.Equal(t, "input", extras.FailureClass)
				if pm == policy.ModeEnforce {
					pe, ok := appplugins.AsPluginError(err)
					require.True(t, ok)
					assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
					assert.Equal(t, decisionFailedClosed, extras.Decision)
					return
				}
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.Equal(t, decisionFailedOpen, extras.Decision)
			})
		}
	}
}

func TestInspectSegmentFailureModeOnAvailabilityFailures(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway} {
		for _, tc := range []struct {
			mode string
			pm   policy.Mode
			cut  bool
		}{
			{"", policy.ModeEnforce, false},
			{"open", policy.ModeEnforce, false},
			{"closed", policy.ModeEnforce, true},
			{"closed", policy.ModeObserve, false},
		} {
			t.Run(http.StatusText(status)+"/"+tc.mode+"/"+string(tc.pm), func(t *testing.T) {
				t.Parallel()
				g := &segmentGuard{status: status}
				p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
				set := withFailureMode(streamingSettings(nil), tc.mode)
				verdict, err := p.InspectSegment(segmentTraceContext(), execInput(policy.StagePreResponse, tc.pm, set, segmentRequest(), nil),
					appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
				require.NoError(t, err)
				require.NotNil(t, verdict)
				assert.Equal(t, tc.cut, verdict.Block)
				if tc.cut {
					assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, verdict.Type)
					require.NotNil(t, verdict.Failure)
					assert.Equal(t, appplugins.FailureClassAvailability, verdict.Failure.Class, "the class stays the real one")
				}
			})
		}
	}
}

func TestInspectSegmentPayloadTooLargeIsTheSameInBothModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{status: http.StatusRequestEntityTooLarge}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			set := withFailureMode(streamingSettings(nil), mode)
			verdict, err := p.InspectSegment(segmentTraceContext(), execInput(policy.StagePreResponse, policy.ModeEnforce, set, segmentRequest(), nil),
				appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
			require.NoError(t, err)
			require.NotNil(t, verdict)
			assert.True(t, verdict.Block)
		})
	}
}

// failure_mode is trustguard's own opt-in: the shared helpers behave as before
// for every other guardrail, which never sets it.
func TestSharedFailureHandlingIsUnchangedWithoutFailClosed(t *testing.T) {
	t.Parallel()
	for _, pm := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		out := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
			Ctx: context.Background(), Plugin: "other", Stage: policy.StagePreRequest, Mode: pm,
			Reason: appplugins.FailureTransport, Err: assert.AnError,
		})
		assert.Equal(t, appplugins.DecisionFailedOpen, out.Decision, pm)
		assert.Equal(t, appplugins.FailureClassAvailability, out.Class)
		assert.Nil(t, out.Err)

		verdict, err := appplugins.ExternalStreamOutcome("other", pm, appplugins.FailureTransport, "", nil, assert.AnError)
		assert.Nil(t, verdict)
		assert.Error(t, err)
	}
}

// failureCase is one way a policy fails before TrustGuard is asked anything.
type failureCase struct {
	name   string
	reason string
	// plugin and settings build the plugin and the policy's settings for the case.
	plugin func(t *testing.T) *Plugin
	set    func(mode string) map[string]any
	req    func() *infracontext.RequestContext
}

func baseSettings(mode string) map[string]any { return withFailureMode(settings(""), mode) }

func preCallFailureCases() []failureCase {
	live := func(t *testing.T) *Plugin {
		return newTestPlugin(t, adapter.NewRegistry(), newServer(t, &fakeGuard{response: GuardResponse{Status: statusAllow}}).URL)
	}
	return []failureCase{
		{"config_invalid via a bad direction", failureReasonConfigInvalid, live,
			func(mode string) map[string]any {
				s := baseSettings(mode)
				s["direction"] = "sideways"
				return s
			}, requestContext},
		{"config_invalid via a stored Closed", failureReasonConfigInvalid, live,
			func(string) map[string]any {
				return map[string]any{"collector_id": testCollectorID, "failure_mode": "Closed"}
			}, requestContext},
		{"base_url_missing", failureReasonBaseURLMissing, func(t *testing.T) *Plugin {
			return newTestPlugin(t, adapter.NewRegistry(), "")
		}, baseSettings, requestContext},
		{"credentials_missing", failureReasonCredentialsMissing, func(t *testing.T) *Plugin {
			return New(adapter.NewRegistry(), "http://guard.local", testTimeout, "", "", nil, withBaseTransport(testTransport(t)))
		}, baseSettings, requestContext},
		{"gateway_id_missing", failureReasonGatewayIDMissing, live, baseSettings, func() *infracontext.RequestContext {
			req := requestContext()
			req.GatewayID = ""
			return req
		}},
	}
}

// A closed policy is refused in enforce and recorded in observe for every
// failure that happens before TrustGuard is called, including settings that do
// not parse. Open, and an unset mode, behave as they always did.
func TestExecuteClosedAppliesToPreCallFailures(t *testing.T) {
	t.Parallel()
	for _, fc := range preCallFailureCases() {
		for _, tc := range []struct {
			mode    string
			pm      policy.Mode
			refused bool
		}{
			{"closed", policy.ModeEnforce, true},
			{"closed", policy.ModeObserve, false},
			{"open", policy.ModeEnforce, false},
			{"", policy.ModeEnforce, false},
		} {
			// "a stored Closed" is closed for the lenient read whatever mode asks.
			stored := fc.name == "config_invalid via a stored Closed"
			refused := tc.refused || (stored && tc.pm == policy.ModeEnforce)
			closed := tc.mode == "closed" || stored
			t.Run(fc.name+"/"+tc.mode+"/"+string(tc.pm), func(t *testing.T) {
				t.Parallel()
				p := fc.plugin(t)
				event, span := newEvent()
				res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, tc.pm, fc.set(tc.mode), fc.req(), nil, event))
				if refused {
					pe, ok := appplugins.AsPluginError(err)
					require.True(t, ok, "want a *PluginError, got %v", err)
					assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
					assert.Nil(t, res)
				} else {
					require.NoError(t, err)
					require.NotNil(t, res)
					assert.Equal(t, http.StatusOK, res.StatusCode)
				}
				extras, ok := span.PluginAttrsCopy().Extras.(guardData)
				require.True(t, ok)
				assert.Equal(t, fc.reason, extras.FailureReason)
				assert.Equal(t, "availability", extras.FailureClass)
				assert.Equal(t, refused, extras.FailedClosed)
				assert.Equal(t, !refused, extras.FailedOpen)
				assert.Equal(t, closed, extras.FailureMode == "closed")
			})
		}
	}
}

func TestFailureModeFromRaw(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   map[string]any
		want string
	}{
		{"nil", nil, "open"},
		{"absent", map[string]any{"x": 1}, "open"},
		{"closed", map[string]any{"failure_mode": "closed"}, "closed"},
		{"any case and spaces", map[string]any{"Failure_Mode": " Closed "}, "closed"},
		{"open", map[string]any{"failure_mode": "open"}, "open"},
		{"garbage", map[string]any{"failure_mode": "fail_closed"}, "open"},
		{"not a string", map[string]any{"failure_mode": true}, "open"},
	} {
		assert.Equal(t, tc.want, failureModeFromRaw(tc.in), tc.name)
	}
}

// Settings that do not parse take the policy off the stream chain, so a
// response streams out with nothing on the record. A closed policy stays on it:
// the parse failure is refused in enforce and recorded in observe.
func TestStreamSettingsOfAClosedPolicyThatDoesNotParse(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://guard.local", time.Second, "id", "secret", nil)
	bad := func(mode string) map[string]any {
		s := map[string]any{"collector_id": "not-a-uuid"}
		if mode != "" {
			s["failure_mode"] = mode
		}
		return s
	}

	acts, opts := p.StreamSettings(bad("closed"))
	assert.True(t, acts)
	assert.Positive(t, opts.HeadChars)

	acts, _ = p.StreamSettings(bad("open"))
	assert.False(t, acts, "open keeps today's behaviour")
	acts, _ = p.StreamSettings(bad(""))
	assert.False(t, acts)

	requestOnly := bad("closed")
	requestOnly["direction"] = legRequest
	acts, _ = p.StreamSettings(requestOnly)
	assert.False(t, acts, "a request-only policy is not on the response leg")
}

func TestInspectSegmentClosedPolicyThatDoesNotParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode string
		pm   policy.Mode
		cut  bool
	}{
		{"closed", policy.ModeEnforce, true},
		{"closed", policy.ModeObserve, false},
		{"open", policy.ModeEnforce, false},
		{"", policy.ModeEnforce, false},
	} {
		t.Run(tc.mode+"/"+string(tc.pm), func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			set := streamingSettings(nil)
			set["collector_id"] = "not-a-uuid"
			withFailureMode(set, tc.mode)
			event, span := newEvent()
			in := execInputWithEvent(policy.StagePreResponse, tc.pm, set, segmentRequest(), nil, event)
			ctx := segmentTraceContext()

			verdict, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
			require.NoError(t, err)
			require.NotNil(t, verdict)
			assert.Equal(t, tc.cut, verdict.Block)
			assert.Empty(t, g.calls(), "nothing is sent to TrustGuard with settings that do not parse")
			if tc.cut {
				require.NotNil(t, verdict.Failure)
				assert.Equal(t, appplugins.FailureClassAvailability, verdict.Failure.Class)
				return
			}
			_, err = p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 2, Closing: true, Report: appplugins.StreamReport{Evals: 1}})
			require.NoError(t, err)
			extras, ok := span.PluginAttrsCopy().Extras.(guardData)
			if tc.mode != "closed" {
				// Open, as always: nothing is recorded for an entry the stream chain never ran.
				assert.False(t, ok && extras.FailureMode != "")
				return
			}
			require.True(t, ok)
			assert.Equal(t, decisionFailedOpen, extras.Decision)
			assert.Equal(t, failureReasonConfigInvalid, extras.FailureReason)
			assert.Equal(t, "availability", extras.FailureClass)
			assert.Equal(t, "closed", extras.FailureMode)
		})
	}
}

// A streamed cut under closed keeps the real class on the entry's record and
// names the mode beside it.
func TestStreamCutUnderClosedRecordsRealClassAndMode(t *testing.T) {
	t.Parallel()
	p := newTestPlugin(t, adapter.NewRegistry(), "")
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, withFailureMode(streamingSettings(nil), "closed"), segmentRequest(), nil, event)
	_, err := p.InspectSegment(segmentTraceContext(), in, appplugins.StreamSegment{Seq: 2, Closing: true, Report: appplugins.StreamReport{
		Evals: 2, CutAtEval: 2, CutOnFailure: true,
		FailureReason: appplugins.FailureTransport, FailureClass: appplugins.FailureClassAvailability,
	}})
	require.NoError(t, err)
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, decisionFailedClosed, extras.Decision)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, "closed", extras.FailureMode)
}

// Open events are byte-identical: failure_mode is never on the wire.
func TestOpenFailureRecordsCarryNoFailureMode(t *testing.T) {
	t.Parallel()
	wire := wireExtras(t, guardData{Decision: decisionFailedOpen, FailureClass: "availability"})
	_, present := wire["failure_mode"]
	assert.False(t, present)
	assert.Equal(t, "closed", wireExtras(t, guardData{FailureMode: "closed"})["failure_mode"])
}
