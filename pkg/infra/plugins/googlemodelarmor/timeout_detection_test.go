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

package googlemodelarmor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// slowStub answers after delay, or as soon as the caller gives up.
func slowStub(t *testing.T, delay time.Duration, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func stalledTokenSource(ctx context.Context) (string, error) {
	<-ctx.Done()
	return "", errors.New("token endpoint gave up")
}

func TestSanitizeFailureOfTimeouts(t *testing.T) {
	t.Parallel()
	fast := slowStub(t, 0, http.StatusOK, allowResponse)
	for _, tc := range []struct {
		name   string
		client func(t *testing.T) *client
		ctx    func() (context.Context, context.CancelFunc)
		detail string
	}{
		{
			name: "token minting stalls past the limit",
			client: func(*testing.T) *client {
				return newClientWithTokenSource(fast.URL, 50*time.Millisecond, stalledTokenSource)
			},
			detail: appplugins.DetailTimeout,
		},
		{
			name: "Model Armor answers after the limit",
			client: func(t *testing.T) *client {
				return newClientWithTokenSource(slowStub(t, 2*time.Second, http.StatusOK, allowResponse).URL,
					50*time.Millisecond, staticTokenSource("t", nil))
			},
			detail: appplugins.DetailTimeout,
		},
		{
			name: "Model Armor answers 504",
			client: func(t *testing.T) *client {
				return newClientWithTokenSource(slowStub(t, 0, http.StatusGatewayTimeout, `{}`).URL,
					time.Second, staticTokenSource("t", nil))
			},
			detail: appplugins.DetailTimeout,
		},
		{
			name: "Model Armor answers 503",
			client: func(t *testing.T) *client {
				return newClientWithTokenSource(slowStub(t, 0, http.StatusServiceUnavailable, `{}`).URL,
					time.Second, staticTokenSource("t", nil))
			},
		},
		{
			name: "credentials refused at once",
			client: func(*testing.T) *client {
				return newClientWithTokenSource(fast.URL, time.Second, staticTokenSource("", errors.New("invalid_grant")))
			},
		},
		{
			name: "the caller cancelled",
			client: func(t *testing.T) *client {
				return newClientWithTokenSource(slowStub(t, 2*time.Second, http.StatusOK, allowResponse).URL,
					time.Second, staticTokenSource("t", nil))
			},
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				time.AfterFunc(50*time.Millisecond, cancel)
				return ctx, cancel
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if tc.ctx != nil {
				ctx, cancel = tc.ctx()
			}
			defer cancel()
			_, err := tc.client(t).SanitizeUserPrompt(ctx, "proj", "us", "tmpl", "hello")
			require.Error(t, err)
			reason, detail := failureOfError(err)
			assert.Equal(t, appplugins.FailureTransport, reason)
			assert.Equal(t, tc.detail, detail)
		})
	}
}

// pluginAt builds a plugin whose client cache honours the per-policy limit, as
// production wiring does, against baseURL with gatewayDefault as
// MODEL_ARMOR_TIMEOUT.
func pluginAt(baseURL string, gatewayDefault time.Duration) *Plugin {
	sources := &credentialSources{
		adc:         func(context.Context, string) (string, error) { return "tok", nil },
		serviceAcct: func(context.Context, string, string) (string, error) { return "tok", nil },
		impersonate: func(context.Context, string, string) (string, error) { return "tok", nil },
	}
	return &Plugin{
		registry:             adapter.NewRegistry(),
		clients:              newModelArmorClientCache(baseURL, sources),
		timeout:              gatewayDefault,
		allowAmbientIdentity: true,
	}
}

func TestExecuteTimeoutAndOutageFollowTheirOwnModes(t *testing.T) {
	t.Parallel()
	slow := slowStub(t, 2*time.Second, http.StatusOK, allowResponse)
	down := slowStub(t, 0, http.StatusServiceUnavailable, `{}`)
	for _, tc := range []struct {
		name        string
		settings    map[string]any
		slow        bool
		mode        policy.Mode
		refused     bool
		decision    string
		failureMode string
	}{
		{"legacy open: outage passes", nil, false, policy.ModeEnforce, false, "failed_open", ""},
		{"legacy open: timeout passes", nil, true, policy.ModeEnforce, false, "failed_open", ""},
		{"legacy closed: outage refused", map[string]any{"failure_mode": "closed"}, false, policy.ModeEnforce, true, "failed_closed", "closed"},
		{"legacy closed: timeout refused", map[string]any{"failure_mode": "closed"}, true, policy.ModeEnforce, true, "failed_closed", "closed"},
		{"block outage, allow slow: outage refused", map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open"}, false, policy.ModeEnforce, true, "failed_closed", "closed"},
		{"block outage, allow slow: timeout passes", map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open"}, true, policy.ModeEnforce, false, "failed_open", ""},
		{"allow outage, block slow: outage passes", map[string]any{"timeout_failure_mode": "closed"}, false, policy.ModeEnforce, false, "failed_open", ""},
		{"allow outage, block slow: timeout refused", map[string]any{"timeout_failure_mode": "closed"}, true, policy.ModeEnforce, true, "failed_closed", "closed"},
		{"observe records a closed timeout", map[string]any{"timeout_failure_mode": "closed"}, true, policy.ModeObserve, false, "failed_open", "closed"},
		{"observe records a closed outage", map[string]any{"failure_mode": "closed"}, false, policy.ModeObserve, false, "failed_open", "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, wantDetail := down, ""
			if tc.slow {
				srv, wantDetail = slow, appplugins.DetailTimeout
			}
			p := pluginAt(srv.URL, 100*time.Millisecond)
			for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
				event, span := newStreamEvent()
				in := execInput(stage, tc.mode, settingsOf(tc.settings), reqCtx(openAIRequest()), respCtx(openAIResponse(), false))
				in.Event = event
				res, err := p.Execute(context.Background(), in)
				if tc.refused {
					pe, ok := appplugins.AsPluginError(err)
					require.True(t, ok, "%s: want a plugin error, got res=%+v err=%v", stage, res, err)
					assert.Equal(t, http.StatusForbidden, pe.StatusCode)
				} else {
					assertPassThrough(t, res, err)
				}
				data, ok := span.PluginAttrsCopy().Extras.(*Data)
				require.True(t, ok, "%s: extras = %T", stage, span.PluginAttrsCopy().Extras)
				assert.Equal(t, tc.decision, data.Decision, stage)
				assert.Equal(t, string(appplugins.FailureTransport), data.FailureReason, stage)
				assert.Equal(t, wantDetail, data.FailureDetail, stage)
				assert.Equal(t, string(appplugins.FailureClassAvailability), data.FailureClass, stage)
				assert.Equal(t, tc.failureMode, data.FailureMode, stage)
			}
		})
	}
}

func settingsOf(kv map[string]any) map[string]any {
	set := modelArmorSettings()
	for k, v := range kv {
		set[k] = v
	}
	return set
}

// timeout_seconds replaces the gateway default for each call, both below and
// above it; empty keeps the default.
func TestExecuteTimeoutSecondsReplacesTheGatewayDefault(t *testing.T) {
	t.Parallel()
	srv := slowStub(t, 1500*time.Millisecond, http.StatusOK, allowResponse)
	for _, tc := range []struct {
		name           string
		gatewayDefault time.Duration
		settings       map[string]any
		decision       string
		detail         string
	}{
		{"1 s limit cuts a 1.5 s answer", 3 * time.Second, map[string]any{"timeout_seconds": 1}, "failed_open", appplugins.DetailTimeout},
		{"empty limit keeps the 3 s default", 3 * time.Second, nil, decisionAllowed, ""},
		{"2 s limit above a 1 s default waits", time.Second, map[string]any{"timeout_seconds": 2}, decisionAllowed, ""},
		{"empty limit keeps the 1 s default", time.Second, nil, "failed_open", appplugins.DetailTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginAt(srv.URL, tc.gatewayDefault)
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsOf(tc.settings), reqCtx(openAIRequest()), nil)
			in.Event = event
			res, err := p.Execute(context.Background(), in)
			assertPassThrough(t, res, err)
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, tc.decision, data.Decision)
			assert.Equal(t, tc.detail, data.FailureDetail)
		})
	}
}

// A streamed block keeps its fixed per-block limit, and a block that runs past
// it follows timeout_failure_mode, whatever timeout_seconds says.
func TestInspectSegmentTimeoutFollowsTheTimeoutMode(t *testing.T) {
	t.Parallel()
	srv := slowStub(t, 3*time.Second, http.StatusOK, allowResponse)
	for _, tc := range []struct {
		name     string
		settings map[string]any
		mode     policy.Mode
		cut      bool
	}{
		{"block outages, allow slow: released", map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open", "timeout_seconds": 30}, policy.ModeEnforce, false},
		{"allow outages, block slow: cut", map[string]any{"timeout_failure_mode": "closed"}, policy.ModeEnforce, true},
		{"legacy closed: cut", map[string]any{"failure_mode": "closed"}, policy.ModeEnforce, true},
		{"legacy open: released", nil, policy.ModeEnforce, false},
		{"observe never cuts", map[string]any{"timeout_failure_mode": "closed"}, policy.ModeObserve, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginAt(srv.URL, 15*time.Second)
			start := time.Now()
			got, err := p.InspectSegment(context.Background(),
				streamInput(tc.mode, settingsOf(tc.settings), nil), segment(1, "a slow paragraph"))
			assert.Less(t, time.Since(start), 2900*time.Millisecond, "the per-block limit applies, not timeout_seconds")
			if tc.cut {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.True(t, got.Block)
				require.NotNil(t, got.Failure)
				assert.Equal(t, appplugins.DetailTimeout, got.Failure.Detail)
				return
			}
			assert.Nil(t, got)
			var typed *appplugins.ExternalStreamFailure
			require.ErrorAs(t, err, &typed)
			assert.Equal(t, appplugins.FailureTransport, typed.Reason)
			assert.Equal(t, appplugins.DetailTimeout, typed.Detail)
		})
	}
}

func TestStreamFailsClosedOn(t *testing.T) {
	t.Parallel()
	p := &Plugin{}
	set := settingsOf(map[string]any{"failure_mode": "closed", "timeout_failure_mode": "open"})
	assert.True(t, p.StreamFailsClosedOn(set, appplugins.FailureTransport, ""))
	assert.False(t, p.StreamFailsClosedOn(set, appplugins.FailureTransport, appplugins.DetailTimeout))

	_, opts := p.StreamSettings(settingsOf(map[string]any{"timeout_failure_mode": "closed"}))
	assert.Equal(t, "fail_closed", opts.OnError, "a policy that can cut some failure is on the stream as fail_closed")
	_, opts = p.StreamSettings(settingsOf(nil))
	assert.NotEqual(t, "fail_closed", opts.OnError)
}
