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
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The token endpoint refusing the gateway's credentials is the same failure as
// /v1/evaluate refusing its token, and the likelier one: a bad secret shows up
// at the token leg first. Both must fail closed whatever on_error says.

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

func TestExecuteTokenRejectionFailsClosed(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		for _, onError := range []string{onErrorFailOpen, onErrorFailClosed} {
			t.Run(http.StatusText(status)+"/"+onError, func(t *testing.T) {
				t.Parallel()
				f := &fakeGuard{tokenStatuses: []int{status}, response: GuardResponse{Status: statusAllow}}
				p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

				set := settings("")
				set["on_error"] = onError
				event, span := newEvent()
				in := execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil, event)
				res, err := p.Execute(context.Background(), in)

				assert.Nil(t, res)
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "a token rejection must fail closed even with on_error=%s, got %v", onError, err)
				assert.Equal(t, http.StatusBadGateway, pe.StatusCode)
				assert.Equal(t, typeUnauthorized, pe.Type)
				var body map[string]any
				require.NoError(t, json.Unmarshal(pe.Body, &body))
				assert.EqualValues(t, status, body["upstream_status"], "the caller sees which status the token leg answered")

				extras, ok := span.PluginAttrsCopy().Extras.(guardData)
				require.True(t, ok)
				assert.True(t, extras.FailedClosed)
				assert.Equal(t, decisionFailedClosed, extras.Decision)
				assert.Equal(t, failureReasonUnauthorized, extras.FailureReason)
				assert.Zero(t, f.count(), "evaluate is never reached without a token")
			})
		}
	}
}

func TestExecuteTokenTransientFailureFollowsOnError(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status)+"/default", func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{tokenStatuses: []int{status}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

			in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)
			res, err := p.Execute(context.Background(), in)
			require.NoError(t, err, "a transient token failure keeps the default fail-open")
			require.NotNil(t, res)
			assert.Equal(t, http.StatusOK, res.StatusCode)
			assert.False(t, res.StopUpstream)
		})
		t.Run(http.StatusText(status)+"/"+onErrorFailClosed, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{tokenStatuses: []int{status}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

			set := settings("")
			set["on_error"] = onErrorFailClosed
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil)
			_, err := p.Execute(context.Background(), in)
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok)
			assert.Equal(t, typeGuardError, pe.Type, "a transient failure is a backend error, not an auth rejection")
		})
	}
}

// TestExecuteTokenRejectionOnRefreshFailsClosed covers guard's second token
// fetch: evaluate refuses the cached token, guard invalidates it and asks for
// another, and the token endpoint now refuses the credentials outright.
func TestExecuteTokenRejectionOnRefreshFailsClosed(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{status: http.StatusUnauthorized, tokenStatuses: []int{http.StatusOK, http.StatusUnauthorized}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)

	set := settings("")
	set["on_error"] = onErrorFailOpen
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil)
	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "a refused refetch must fail closed, got %v", err)
	assert.Equal(t, typeUnauthorized, pe.Type)
	assert.Equal(t, 1, f.count(), "one evaluate before the refetch, none after it")
}

// TestExecuteTokenRejectionIsNotCached pins recovery: once the credentials are
// fixed the next request goes through, rather than replaying a stored refusal.
func TestExecuteTokenRejectionIsNotCached(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{tokenStatuses: []int{http.StatusUnauthorized}, response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil)

	_, err := p.Execute(context.Background(), in)
	_, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "first call fails closed, got %v", err)

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.False(t, res.StopUpstream)
	assert.Equal(t, 1, f.count(), "the second call fetched a fresh token and reached evaluate")
}

// TestExecuteMissingCredentialsFailsClosed: a policy cannot be saved without
// TRUSTGUARD_CLIENT_ID/SECRET, so a pod that has none is running a guard it
// cannot call. That is a deployment fault, not a transient one, and on_error
// does not relax it.
func TestExecuteMissingCredentialsFailsClosed(t *testing.T) {
	t.Parallel()

	for _, onError := range []string{onErrorFailOpen, onErrorFailClosed} {
		t.Run(onError, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			p := New(adapter.NewRegistry(), newServer(t, f).URL, testTimeout, "", "", nil, withBaseTransport(testTransport(t)))

			set := settings("")
			set["on_error"] = onError
			event, span := newEvent()
			in := execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil, event)
			res, err := p.Execute(context.Background(), in)

			assert.Nil(t, res)
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok, "missing credentials must fail closed with on_error=%s, got %v", onError, err)
			assert.Equal(t, http.StatusBadGateway, pe.StatusCode)
			assert.Equal(t, typeUnauthorized, pe.Type)
			var body map[string]any
			require.NoError(t, json.Unmarshal(pe.Body, &body))
			assert.NotContains(t, body, "upstream_status", "TrustGuard was never asked, so there is no upstream status to report")
			assert.Zero(t, f.count())

			extras, ok := span.PluginAttrsCopy().Extras.(guardData)
			require.True(t, ok)
			assert.True(t, extras.FailedClosed)
			assert.Equal(t, decisionFailedClosed, extras.Decision)
			assert.Equal(t, directionInput, extras.Direction)
			assert.Equal(t, failureReasonCredentialsMissing, extras.FailureReason)
		})
	}
}

// TestExecuteMissingCredentialsBlocksInObserveMode pins the same contract the
// rate-limit and auth rejections have: observe relaxes findings, not a guard
// the gateway cannot call.
func TestExecuteMissingCredentialsBlocksInObserveMode(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := New(adapter.NewRegistry(), newServer(t, f).URL, testTimeout, "", "", nil, withBaseTransport(testTransport(t)))

	in := execInput(policy.StagePreRequest, policy.ModeObserve, settings(""), requestContext(), nil)
	_, err := p.Execute(context.Background(), in)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "missing credentials must block even in observe mode, got %v", err)
	assert.Equal(t, typeUnauthorized, pe.Type)
}

// TestExecuteMissingCredentialsLeavesUninspectedTrafficAlone: the check sits
// after the skips, so a request the plugin would have passed without a call
// anyway is not turned into an outage by a missing credential.
func TestExecuteMissingCredentialsLeavesUninspectedTrafficAlone(t *testing.T) {
	t.Parallel()

	f := &fakeGuard{}
	p := New(adapter.NewRegistry(), newServer(t, f).URL, testTimeout, "", "", nil, withBaseTransport(testTransport(t)))

	req := requestContext()
	req.GatewayID = ""
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event)
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.False(t, res.StopUpstream)
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Empty(t, extras.FailureReason, "a missing gateway id is the reason this request went uninspected")
}

func TestInspectSegmentMissingCredentialsBlocks(t *testing.T) {
	t.Parallel()

	g := &segmentGuard{response: GuardResponse{Status: statusAllow}}
	srv := newSegmentServer(t, g)
	p := New(adapter.NewRegistry(), srv.URL, testClientTimeout, "", "", nil, withBaseTransport(testTransport(t)))
	set := streamingSettings(map[string]any{"on_error": onErrorFailOpen})
	verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
		appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.True(t, verdict.Block, "missing credentials must not be left to streaming.on_error")
	assert.Equal(t, typeUnauthorized, verdict.Type)
	assert.Empty(t, g.calls())
}

func TestInspectSegmentTokenRejectionIgnoresOnError(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			g := &segmentGuard{tokenStatus: status, response: GuardResponse{Status: statusAllow}}
			p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
			set := streamingSettings(map[string]any{"on_error": onErrorFailOpen})
			verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
				appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
			require.NoError(t, err)
			require.NotNil(t, verdict)
			assert.True(t, verdict.Block, "a token rejection must not be left to streaming.on_error")
			assert.Equal(t, typeUnauthorized, verdict.Type)
			assert.Empty(t, g.calls())
		})
	}

	t.Run(http.StatusText(http.StatusInternalServerError), func(t *testing.T) {
		t.Parallel()
		g := &segmentGuard{tokenStatus: http.StatusInternalServerError}
		p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
		set := streamingSettings(map[string]any{"on_error": onErrorFailOpen})
		verdict, err := p.InspectSegment(segmentTraceContext(), segmentInput(t, set),
			appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
		require.Error(t, err)
		assert.Nil(t, verdict, "a transient token failure is the caller's to resolve")
	})
}
