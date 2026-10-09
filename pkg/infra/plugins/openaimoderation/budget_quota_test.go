// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package openaimoderation

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// The error bodies are OpenAI's documented ones: an account out of credit
// answers 429 with code insufficient_quota, and a spent hard limit with
// billing_hard_limit_reached, which is a different thing from the rate limit in
// rateLimited.
const (
	insufficientQuota = `{"error":{"message":"You exceeded your current quota, please check your plan and billing details.","type":"insufficient_quota","param":null,"code":"insufficient_quota"}}`
	billingHardLimit  = `{"error":{"message":"Billing hard limit has been reached","type":"invalid_request_error","param":null,"code":"billing_hard_limit_reached"}}`
	moderationAllowed = `{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"hate":false},"category_scores":{"hate":0.01}}]}`
)

func withMarker(text string, at int) string {
	return text[:at] + " HANG-HERE " + text[at:]
}

func answeringServer(t *testing.T, handle func(n int32, w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server only notices a client that left once the body is read.
		raw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		w.Header().Set("Content-Type", "application/json")
		handle(calls.Add(1), w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// An exhausted account is configuration: nothing the request does changes it,
// so it fails open however many chunks the request has, where a rate limit on a
// request of several chunks is input.
func TestAnExhaustedQuotaIsConfigurationNotAThrottle(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{"insufficient_quota": insufficientQuota, "billing_hard_limit_reached": billingHardLimit} {
		for _, kib := range []int{1, 300} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				srv := answeringServer(t, func(n int32, w http.ResponseWriter, _ *http.Request) {
					if n == 3 || kib == 1 {
						w.WriteHeader(http.StatusTooManyRequests)
						_, _ = w.Write([]byte(body))
						return
					}
					_, _ = w.Write([]byte(moderationAllowed))
				})
				p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
				event, span := newEvent()
				in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, benignText(kib)), nil, event)

				res, err := p.Execute(context.Background(), in)

				require.NoError(t, err)
				require.NotNil(t, res)
				extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
				require.True(t, ok)
				assert.Equal(t, string(appplugins.FailureConfigInvalid), extras.FailureReason)
				assert.Equal(t, appplugins.DetailProviderQuotaExhausted, extras.FailureDetail)
				assert.Equal(t, "availability", extras.FailureClass)
				assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
			})
		}
	}
}

// The chunks after the first round wait for this request's own earlier chunks.
// A provider that hangs on one of them ran the budget out with its own time, so
// the cut is availability, not the request's size.
func TestAProviderHangOnAChunkThatWaitedIsAvailability(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			// The marker sits in a chunk that waits behind the first round.
			srv := answeringServer(t, func(_ int32, w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "HANG-HERE") {
					<-r.Context().Done()
					return
				}
				_, _ = w.Write([]byte(moderationAllowed))
			})
			p := New(adapter.NewRegistry(), srv.URL, 3*time.Second, nil)
			event, span := newEvent()
			in := execInput(policy.StagePreRequest, mode, blockSettings(), chatRequestOf(t, withMarker(benignText(150), 130<<10)), nil, event)

			res, err := p.Execute(context.Background(), in)

			require.NoError(t, err, "a hang is availability and fails open")
			require.NotNil(t, res)
			extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
			require.True(t, ok)
			assert.Equal(t, "availability", extras.FailureClass)
			assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
		})
	}
}

func TestASlowProviderOnAChunkOfTheFirstRoundIsAvailability(t *testing.T) {
	t.Parallel()
	srv := answeringServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(moderationAllowed))
	})
	p := New(adapter.NewRegistry(), srv.URL, time.Second, nil)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, benignText(100)), nil, event)

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
}

// A client that left is not the request's content.
func TestAClientThatLeavesIsNeverInput(t *testing.T) {
	t.Parallel()
	srv := answeringServer(t, func(n int32, w http.ResponseWriter, r *http.Request) {
		if n > evalParallel {
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(moderationAllowed))
	})
	p := New(adapter.NewRegistry(), srv.URL, 5*time.Second, nil)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, benignText(150)), nil, event)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(400*time.Millisecond, cancel)

	res, err := p.Execute(ctx, in)

	require.NoError(t, err)
	require.NotNil(t, res)
	extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
}
