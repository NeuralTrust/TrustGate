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

package a2a_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sendTraced sends body and returns the attributes of the a2a span it left.
func sendTraced(t *testing.T, h *harness, body []byte, timeout time.Duration) trace.A2AAttrs {
	t.Helper()
	rt := trace.New("trace", trace.Metadata{})
	ctx := trace.NewContext(context.Background(), rt)
	if x, rpcErr := h.forwarder.Prepare(ctx, h.call(t, body, nil)); rpcErr == nil {
		sendCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		_, _ = x.Send(sendCtx)
	}
	spans := rt.Spans()
	require.Len(t, spans, 1)
	assert.Equal(t, trace.SpanA2A, spans[0].Type)
	assert.False(t, spans[0].EndedAt().IsZero(), "the span is ended")
	attrs, ok := spans[0].A2AAttrsCopy()
	require.True(t, ok)
	return attrs
}

func TestSpanOfACompletedCall(t *testing.T) {
	t.Parallel()
	ag := newAgent(t, answer(v03TaskAnswer()))
	h := newHarness(t, a2a.Version03, ag.URL, allow)
	attrs := sendTraced(t, h, rpcRequest("message/send", `{"message":{"parts":[]}}`), time.Minute)
	assert.Equal(t, trace.A2AAttrs{
		Method:              "message/send",
		RegistryID:          h.agent.ID.String(),
		AgentName:           "Travel planner",
		ProtocolVersion:     "0.3",
		TaskID:              v03Task,
		ContextID:           v03Context,
		TaskState:           "working",
		UpstreamStatus:      http.StatusOK,
		Outcome:             a2a.OutcomeOK,
		IdentityMode:        "none",
		IdentitySubjectKind: a2a.SubjectApp,
	}, attrs)
}

func TestSpanOutcomes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		agent   http.HandlerFunc
		exec    executorFunc
		body    []byte
		setup   func(*harness)
		timeout time.Duration
		want    func(*testing.T, trace.A2AAttrs)
	}{
		{
			name: "another caller's task",
			body: rpcRequest("tasks/get", `{"id":"`+v03Task+`"}`),
			setup: func(h *harness) {
				o := h.owner()
				o.Subject = "someone-else"
				h.store.set(h, a2a.ScopeTask, v03Task, o)
			},
			want: func(t *testing.T, a trace.A2AAttrs) {
				assert.Equal(t, a2a.OutcomeNotFound, a.Outcome)
				assert.Equal(t, a2a.ReasonNotOwner, a.Reason)
				assert.Equal(t, int(a2a.CodeTaskNotFound), a.RPCErrorCode)
				assert.Zero(t, a.UpstreamStatus)
			},
		},
		{
			name: "blocked",
			body: rpcRequest("message/send", `{"message":{"parts":[{"kind":"text","text":"4111 1111 1111 1111"}]}}`),
			exec: func(context.Context, appplugins.StageInput) (*appplugins.StageOutcome, error) {
				return nil, &appplugins.PluginError{StatusCode: http.StatusForbidden, Type: appplugins.TypeMaskUnsupported, Plugin: "trustguard"}
			},
			want: func(t *testing.T, a trace.A2AAttrs) {
				assert.Equal(t, a2a.OutcomeBlocked, a.Outcome)
				assert.Equal(t, a2a.ReasonMaskUnsupported, a.Reason)
				assert.Equal(t, "trustguard", a.BlockedBy)
			},
		},
		{
			name: "refused",
			body: rpcRequest("tasks/pushNotificationConfig/set", `{}`),
			want: func(t *testing.T, a trace.A2AAttrs) {
				assert.Equal(t, a2a.OutcomeRefused, a.Outcome)
				assert.Equal(t, int(a2a.CodePushNotificationNotSupported), a.RPCErrorCode)
			},
		},
		{
			name:    "slow agent",
			agent:   func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() },
			body:    rpcRequest("message/send", `{"message":{"parts":[]}}`),
			timeout: 50 * time.Millisecond,
			want: func(t *testing.T, a trace.A2AAttrs) {
				assert.Equal(t, a2a.OutcomeUpstreamTimeout, a.Outcome)
				assert.Equal(t, a2a.ReasonUpstreamTimeout, a.Reason)
			},
		},
		{
			name:  "agent error",
			agent: answer(readFixture(t, "v03.task_not_found.response.json")),
			body:  rpcRequest("message/send", `{"message":{"parts":[]}}`),
			want: func(t *testing.T, a trace.A2AAttrs) {
				assert.Equal(t, a2a.OutcomeUpstreamError, a.Outcome)
				assert.Equal(t, int(a2a.CodeTaskNotFound), a.RPCErrorCode)
			},
		},
	}
	for _, tc := range cases {
		handler := tc.agent
		if handler == nil {
			handler = answer(v03TaskAnswer())
		}
		exec := tc.exec
		if exec == nil {
			exec = allow
		}
		timeout := tc.timeout
		if timeout == 0 {
			timeout = time.Minute
		}
		ag := newAgent(t, handler)
		h := newHarness(t, a2a.Version03, ag.URL, exec)
		if tc.setup != nil {
			tc.setup(h)
		}
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, sendTraced(t, h, tc.body, timeout))
		})
	}
}
