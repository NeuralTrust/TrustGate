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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The token endpoint refusing the gateway's credentials is the same failure as
// /v1/evaluate refusing its token, and the likelier one: a bad secret shows up
// at the token leg first. Like every failure of the guard it fails open: the
// request carries on and the span says why, whatever on_error a stored policy
// still carries.

func TestTokenFetchSortsRejectionsFromTransientFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status   int
		rejected bool
	}{
		{http.StatusBadRequest, true},
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		// An ingress or a wrong base URL answering, not the guard: evaluate
		// fails these open too, and blocking every request on one would turn a
		// routing blip into an outage.
		{http.StatusNotFound, false},
		{http.StatusMethodNotAllowed, false},
		{http.StatusMisdirectedRequest, false},
		{http.StatusRequestTimeout, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, false},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(`{"error":"invalid_scope"}`))
			}))
			t.Cleanup(srv.Close)

			m := newTokenManager(srv.Client(), "id", "secret")
			_, err := m.fetch(context.Background(), testTokenParams(srv.URL))
			require.Error(t, err)
			var auth *authRejectedError
			if !tt.rejected {
				assert.False(t, errors.As(err, &auth), "a transient %d must stay on the on_error path", tt.status)
				return
			}
			require.True(t, errors.As(err, &auth), "a %d from the token endpoint is a rejection, got %v", tt.status, err)
			assert.Equal(t, tt.status, auth.status)
			assert.Equal(t, "invalid_scope", auth.code, "the OAuth code tells a bad secret from a malformed request")
			assert.False(t, errors.Is(err, errUnauthorized),
				"errUnauthorized sends guard to refetch the token, which cannot help when the token leg itself refused")
		})
	}
}

func TestOAuthErrorCodeKeepsOnlyWellFormedCodes(t *testing.T) {
	t.Parallel()

	for body, want := range map[string]string{
		`{"error":"invalid_client"}`:                                   "invalid_client",
		`{"error":"invalid_scope","error_description":"no such"}`:      "invalid_scope",
		`{"error":"Invalid Client\nlevel=ERROR"}`:                      "",
		`{"error":"` + strings.Repeat("a", maxOAuthErrorCode+1) + `"}`: "",
		`not json`: "",
		``:         "",
	} {
		assert.Equal(t, want, oauthErrorCode([]byte(body)), "body %q", body)
	}
}

func TestExecuteTokenRejectionFailsOpen(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status)+"/default", func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{tokenStatuses: []int{status}, response: GuardResponse{Status: statusAllow}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

			event, span := newEvent()
			in := execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil, event)
			res, err := p.Execute(context.Background(), in)
			require.NoError(t, err)
			assertFailedOpen(t, res, span, failureReasonUnauthorized)
			assert.Zero(t, f.count(), "evaluate is never reached without a token")
		})
		t.Run(http.StatusText(status)+"/stored fail_closed", func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{tokenStatuses: []int{status}, response: GuardResponse{Status: statusAllow}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

			set := settings("")
			set["on_error"] = "fail_closed"
			event, span := newEvent()
			in := execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil, event)
			res, err := p.Execute(context.Background(), in)
			require.NoError(t, err)
			assertFailedOpen(t, res, span, failureReasonUnauthorized)
		})
	}
}

func TestExecuteTokenTransientFailureFailsOpen(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status)+"/default", func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{tokenStatuses: []int{status}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

			event, span := newEvent()
			in := execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil, event)
			res, err := p.Execute(context.Background(), in)
			require.NoError(t, err)
			assertFailedOpen(t, res, span, failureReasonTransport)
		})
		t.Run(http.StatusText(status)+"/stored fail_closed", func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{tokenStatuses: []int{status}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

			set := settings("")
			set["on_error"] = "fail_closed"
			event, span := newEvent()
			res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil, event))
			require.NoError(t, err)
			assertFailedOpen(t, res, span, failureReasonTransport)
		})
	}
}

// TestExecuteTokenRejectionOnRefreshFailsOpen covers guard's second token
// fetch: evaluate refuses the cached token, guard invalidates it and asks for
// another, and the token endpoint now refuses the credentials outright.
func TestExecuteTokenRejectionOnRefreshFailsOpen(t *testing.T) {
	t.Parallel()

	for _, onError := range []string{"fail_open", "fail_closed"} {
		t.Run(onError, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{status: http.StatusUnauthorized, tokenStatuses: []int{http.StatusOK, http.StatusUnauthorized}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

			set := settings("")
			set["on_error"] = onError
			event, span := newEvent()
			res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil, event))
			require.NoError(t, err)
			assertFailedOpen(t, res, span, failureReasonUnauthorized)
			assert.Equal(t, 1, f.count(), "one evaluate before the refetch, none after it")
		})
	}
}

// TestExecuteTokenRejectionIsNotCached pins recovery: once the credentials are
// fixed the next request is inspected again, rather than replaying a refusal.
func TestExecuteTokenRejectionIsNotCached(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{tokenStatuses: []int{http.StatusUnauthorized}, response: GuardResponse{Status: statusBlock}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err, "first call fails open")
	require.NotNil(t, res)
	assert.Zero(t, f.count())

	_, err = p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "the second call fetched a fresh token and reached the guard, which blocks: got %v", err)
	assert.Equal(t, typeBlocked, pe.Type)
	assert.Equal(t, 1, f.count())
}

// TestExecuteNotConfiguredFailsOpen: a pod with no TrustGuard URL or no
// credentials cannot call the guard. That is a failure of the guard, not a
// finding, so it fails open like any other.
func TestExecuteNotConfiguredFailsOpen(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		build  func(t *testing.T, url string) *Plugin
		reason string
	}{
		"credentials missing": {func(t *testing.T, url string) *Plugin {
			return New(adapter.NewRegistry(), url, testTimeout, "", "", nil, withBaseTransport(testTransport(t)))
		}, failureReasonCredentialsMissing},
		"base url missing": {func(t *testing.T, _ string) *Plugin {
			return New(adapter.NewRegistry(), "", testTimeout, "test-client", "test-secret", nil, withBaseTransport(testTransport(t)))
		}, failureReasonBaseURLMissing},
	}
	for name, tc := range cases {
		t.Run(name+"/default", func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
			p := tc.build(t, newServer(t, f).URL)

			event, span := newEvent()
			res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil, event))
			require.NoError(t, err)
			assertFailedOpen(t, res, span, tc.reason)
			assert.Zero(t, f.count())
		})
		t.Run(name+"/stored fail_closed", func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			p := tc.build(t, newServer(t, f).URL)

			set := settings("")
			set["on_error"] = "fail_closed"
			event, span := newEvent()
			res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil, event))
			require.NoError(t, err)
			assertFailedOpen(t, res, span, tc.reason)
		})
	}
}

// TestExecuteNotConfiguredLeavesUninspectedTrafficAlone: the check sits after
// the skips, so a request the plugin would have passed without a call anyway
// is not counted as having gone through for want of configuration.
func TestExecuteNotConfiguredLeavesUninspectedTrafficAlone(t *testing.T) {
	t.Parallel()

	p := New(adapter.NewRegistry(), "", testTimeout, "", "", nil, withBaseTransport(testTransport(t)))
	req := requestContext()
	req.GatewayID = ""
	set := settings("")
	event, span := newEvent()
	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, set, req, nil, event))
	require.NoError(t, err)
	assertFailedOpen(t, res, span, failureReasonGatewayIDMissing)
}

// TestExecuteUnparseableSettingsFailOpen: settings that do not parse must not cut
// the request.
func TestExecuteUnparseableSettingsFailOpen(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusBlock}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	set := settings("")
	set["direction"] = "sideways"
	event, span := newEvent()
	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil, event))
	require.NoError(t, err)
	assertFailedOpen(t, res, span, failureReasonConfigInvalid)
	assert.Zero(t, f.count())
}

// On the streaming path a failure of the guard allows the block, so the rest of
// the chain still inspects it, whatever streaming.on_error a stored policy
// still carries.
func TestInspectSegmentFailuresFailOpen(t *testing.T) {
	t.Parallel()

	type build func(t *testing.T, g *segmentGuard) *Plugin
	withTokenStatus := func(status int) build {
		return func(t *testing.T, g *segmentGuard) *Plugin {
			g.tokenStatus = status
			return newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
		}
	}
	cases := map[string]build{
		"credentials missing": func(t *testing.T, g *segmentGuard) *Plugin {
			return New(adapter.NewRegistry(), newSegmentServer(t, g).URL, testClientTimeout, "", "", nil, withBaseTransport(testTransport(t)))
		},
		"base url missing": func(t *testing.T, g *segmentGuard) *Plugin {
			newSegmentServer(t, g)
			return New(adapter.NewRegistry(), "", testClientTimeout, "test-client", "test-secret", nil, withBaseTransport(testTransport(t)))
		},
		"token 400": withTokenStatus(http.StatusBadRequest),
		"token 401": withTokenStatus(http.StatusUnauthorized),
		"token 403": withTokenStatus(http.StatusForbidden),
		"token 500": withTokenStatus(http.StatusInternalServerError),
	}
	for name, newPlugin := range cases {
		for _, onError := range []string{"fail_open", "fail_closed"} {
			t.Run(name+"/"+onError, func(t *testing.T) {
				t.Parallel()
				g := &segmentGuard{response: GuardResponse{Status: statusBlock}}
				p := newPlugin(t, g)
				set := streamingSettings(map[string]any{"on_error": onError})
				verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
					appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
				assert.Empty(t, g.calls(), "evaluate is never reached")
				require.NoError(t, err)
				require.NotNil(t, verdict)
				assert.False(t, verdict.Block)
			})
		}
	}
}

// TestInspectSegmentPublishesFailOpenOnClosing: a block let through because the
// guard failed is written onto the stream's span when the stream closes, so the
// console shows the stream as failed open, and why, not as a clean pass.
func TestInspectSegmentPublishesFailOpenOnClosing(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{tokenStatus: http.StatusUnauthorized}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, streamingSettings(nil), segmentRequest(), nil, event)
	ctx := segmentTraceContext()

	verdict, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
	require.NoError(t, err)
	require.False(t, verdict.Block)

	_, err = p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Closing: true, Report: appplugins.StreamReport{Evals: 1, GuardCalls: 1}})
	require.NoError(t, err)

	attrs := span.PluginAttrsCopy()
	data, ok := attrs.Extras.(guardData)
	require.True(t, ok)
	assert.True(t, data.FailedOpen)
	assert.Equal(t, failureReasonUnauthorized, data.FailureReason)
	assert.Equal(t, decisionFailedOpen, attrs.Decision)

	key, ok := streamFailureKey(ctx, in, appplugins.StreamSegment{Seq: 1})
	require.True(t, ok)
	_, loaded := p.streamFailures.Load(key)
	assert.False(t, loaded, "the closing segment takes the entry out")
}

// TestInspectSegmentRetiresAfterConsecutiveFailures bounds what a hung guard
// costs a stream: failing open hides the failures from the stream guard, so
// the plugin stops calling on its own after streamRetireAfter in a row, and the
// closing event says the loop retired.
func TestInspectSegmentRetiresAfterConsecutiveFailures(t *testing.T) {
	t.Parallel()

	var tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			tokenCalls.Add(1)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, streamingSettings(nil), segmentRequest(), nil, event)
	ctx := segmentTraceContext()

	for seq := 1; seq <= streamRetireAfter+3; seq++ {
		verdict, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: seq, Accumulated: "Hello world"})
		require.NoError(t, err)
		require.False(t, verdict.Block)
	}
	assert.EqualValues(t, streamRetireAfter, tokenCalls.Load(), "no call after the loop retired")

	_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: streamRetireAfter + 3, Closing: true,
		Report: appplugins.StreamReport{Evals: streamRetireAfter + 3}})
	require.NoError(t, err)
	data := span.PluginAttrsCopy().Extras.(guardData)
	assert.True(t, data.FailedOpen)
	assert.Equal(t, failureReasonUnauthorized, data.FailureReason)
	require.NotNil(t, data.Streaming)
	assert.Equal(t, fallbackReasonSegmentationUnavail, data.Streaming.FallbackReason)
}

// A block the guard did answer resets the run, so intermittent failures never
// retire the loop; the stream still reports that some blocks went through.
func TestInspectSegmentRecoveryResetsTheFailureRun(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	in := segmentInput(t, streamingSettings(nil))
	ctx := segmentTraceContext()
	seg := appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"}

	for i := 0; i < streamRetireAfter-1; i++ {
		p.streamFailed(ctx, in, seg, failureReasonTransport)
	}
	_, err := p.InspectSegment(ctx, in, seg)
	require.NoError(t, err)
	p.streamFailed(ctx, in, seg, failureReasonTransport)
	assert.False(t, p.streamRetired(ctx, in, seg), "the answered block reset the run")

	key, ok := streamFailureKey(ctx, in, seg)
	require.True(t, ok)
	v, ok := p.streamFailures.Load(key)
	require.True(t, ok)
	assert.Equal(t, 1, v.(*streamFailure).consecutive)
}

func TestInspectSegmentUnparseableSettingsAllow(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusBlock}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	set := streamingSettings(nil)
	set["direction"] = "sideways"
	for _, closing := range []bool{false, true} {
		verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world", Closing: closing})
		require.NoError(t, err, "an error here would stop the rest of the chain")
		require.NotNil(t, verdict)
		assert.False(t, verdict.Block)
	}
	assert.Empty(t, g.calls())
}

func TestSweepStreamFailuresDropsExpiredEntries(t *testing.T) {
	t.Parallel()

	p := newTestPlugin(t, adapter.NewRegistry(), "http://unused")
	now := time.Now()
	p.streamFailures.Store("old", &streamFailure{reason: failureReasonTransport, at: now.Add(-streamFailureTTL - time.Second)})
	p.streamFailures.Store("fresh", &streamFailure{reason: failureReasonTransport, at: now})

	p.sweepStreamFailures(now)
	_, old := p.streamFailures.Load("old")
	_, fresh := p.streamFailures.Load("fresh")
	assert.False(t, old)
	assert.True(t, fresh)
}

// Without a stream identity (telemetry off, so no trace) every stream would
// share one key. Nothing is recorded then, so one stream's failures can never
// retire inspection for another.
func TestInspectSegmentWithoutStreamIdentityKeepsNoRecord(t *testing.T) {
	t.Parallel()

	var failing atomic.Bool
	failing.Store(true)
	var evaluateCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == tokenPath {
			if failing.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", contentTypeJSON)
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600})
			return
		}
		evaluateCalls.Add(1)
		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(GuardResponse{Status: statusAllow})
	}))
	t.Cleanup(srv.Close)
	p := newTestPlugin(t, adapter.NewRegistry(), srv.URL)
	in := segmentInput(t, streamingSettings(nil))
	ctx := context.Background()

	for seq := 1; seq <= streamRetireAfter+1; seq++ {
		_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: seq, Accumulated: "one stream"})
		require.NoError(t, err)
	}
	failing.Store(false)
	_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "another stream"})
	require.NoError(t, err)
	assert.EqualValues(t, 1, evaluateCalls.Load(), "the other stream is still inspected")
}
