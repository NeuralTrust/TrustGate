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

package otlp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
)

func TestEventToRecord_A2AAttributes(t *testing.T) {
	t.Parallel()
	evt := &events.Event{
		SchemaVersion: events.SchemaVersion,
		Kind:          events.KindA2A,
		TraceID:       "trace-a2a",
		GatewayID:     "gw-1",
		Status:        events.Status{Code: http.StatusOK},
		Request:       events.Request{Method: "POST", Path: "/bot/agents/reg-1"},
		Response:      events.Response{StatusCode: http.StatusOK},
		A2A: &events.A2A{
			Method:              "SendMessage",
			RegistryID:          "reg-1",
			AgentName:           "Travel planner",
			Provider:            "azure_foundry",
			ProtocolVersion:     "1.0",
			TaskID:              "t-1",
			ContextID:           "c-1",
			TaskState:           "TASK_STATE_COMPLETED",
			UpstreamStatus:      http.StatusOK,
			Outcome:             "blocked",
			Reason:              "policy_blocked",
			BlockedBy:           "trustguard",
			IdentityMode:        "delegation",
			IdentitySubjectKind: "user",
			RPCErrorCode:        -32090,
		},
	}

	attrs := attrsOf(eventToRecord(evt))

	assert.Equal(t, events.KindA2A, attrs[attrKind].AsString())
	for key, want := range map[string]string{
		attrA2AMethod:              "SendMessage",
		attrA2ARegistryID:          "reg-1",
		attrA2AAgentName:           "Travel planner",
		attrA2AProvider:            "azure_foundry",
		attrA2AProtocolVersion:     "1.0",
		attrA2ATaskID:              "t-1",
		attrA2AContextID:           "c-1",
		attrA2ATaskState:           "TASK_STATE_COMPLETED",
		attrA2AOutcome:             "blocked",
		attrA2AReason:              "policy_blocked",
		attrA2ABlockedBy:           "trustguard",
		attrA2AIdentityMode:        "delegation",
		attrA2AIdentitySubjectKind: "user",
	} {
		assert.Equal(t, want, attrs[key].AsString(), key)
	}
	assert.Equal(t, int64(http.StatusOK), attrs[attrA2AUpstreamStatus].AsInt64())
	assert.Equal(t, int64(-32090), attrs[attrA2ARPCErrorCode].AsInt64())
}

func TestEventToRecord_OtherKindsHaveNoA2AAttributes(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{events.KindLLM, events.KindMCP} {
		evt := fullEvent()
		evt.Kind = kind
		for key := range attrsOf(eventToRecord(evt)) {
			assert.False(t, strings.HasPrefix(key, "trustgate.a2a."), "%s record carries %s", kind, key)
		}
	}
}
