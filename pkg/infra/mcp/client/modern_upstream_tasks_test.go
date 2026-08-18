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

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

const upstreamTaskID = "u-123"

func recordingTaskUpstream(t *testing.T, result string) (*modernUpstream, *modernWireRecorder) {
	t.Helper()
	recorder := &modernWireRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		recorder.add(request)
		writeModernResult(t, w, request.id, result)
	}))
	t.Cleanup(srv.Close)
	return newTestModernUpstream(t, srv.URL+"/mcp", sharedHTTPTransport), recorder
}

func lastWireRequest(t *testing.T, recorder *modernWireRecorder) modernWireRequest {
	t.Helper()
	requests := recorder.snapshot()
	if len(requests) == 0 {
		t.Fatal("no request reached the upstream")
	}
	return requests[len(requests)-1]
}

func taskParamsFrom(t *testing.T, request modernWireRequest) map[string]json.RawMessage {
	t.Helper()
	var params map[string]json.RawMessage
	if err := json.Unmarshal(request.params, &params); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	return params
}

// Every tasks/* call carries the real upstream task id, never the northbound
// handle, and routes itself with the Mcp-Method/Mcp-Name pair.
func TestModernUpstreamTaskCallsCarryUpstreamIDAndHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method string
		call   func(ctx context.Context, up *modernUpstream, ref appmcp.TaskRef) error
	}{
		{
			name:   "tasks/get",
			method: appmcp.MethodTasksGet,
			call: func(ctx context.Context, up *modernUpstream, ref appmcp.TaskRef) error {
				_, err := up.GetTask(ctx, ref)
				return err
			},
		},
		{
			name:   "tasks/update",
			method: appmcp.MethodTasksUpdate,
			call: func(ctx context.Context, up *modernUpstream, ref appmcp.TaskRef) error {
				_, err := up.UpdateTask(ctx, ref, json.RawMessage(`{"q1":{"content":{}}}`))
				return err
			},
		},
		{
			name:   "tasks/cancel",
			method: appmcp.MethodTasksCancel,
			call: func(ctx context.Context, up *modernUpstream, ref appmcp.TaskRef) error {
				_, err := up.CancelTask(ctx, ref)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			upstream, recorder := recordingTaskUpstream(t, `{"taskId":"`+upstreamTaskID+`","status":"working"}`)
			ref := appmcp.TaskRef{TaskID: upstreamTaskID, Exposed: "find", Upstream: "search"}

			if err := tt.call(context.Background(), upstream, ref); err != nil {
				t.Fatalf("%s: %v", tt.method, err)
			}

			request := lastWireRequest(t, recorder)
			if request.method != tt.method {
				t.Fatalf("method = %q, want %q", request.method, tt.method)
			}
			var taskID string
			if err := json.Unmarshal(taskParamsFrom(t, request)["taskId"], &taskID); err != nil {
				t.Fatalf("decode taskId: %v", err)
			}
			if taskID != upstreamTaskID {
				t.Fatalf("taskId = %q, want the upstream id", taskID)
			}
			if got := request.headers.Get("Mcp-Method"); got != tt.method {
				t.Fatalf("Mcp-Method = %q, want %q", got, tt.method)
			}
			if got := request.headers.Get("Mcp-Name"); got != upstreamTaskID {
				t.Fatalf("Mcp-Name = %q, want the upstream id", got)
			}
		})
	}
}

// tasks/update forwards the client's answers to the upstream task.
func TestModernUpstreamUpdateTaskForwardsInputResponses(t *testing.T) {
	t.Parallel()
	upstream, recorder := recordingTaskUpstream(t, `{"taskId":"`+upstreamTaskID+`","status":"working"}`)
	inputs := json.RawMessage(`{"q1":{"action":"accept","content":{"city":"Madrid"}}}`)

	if _, err := upstream.UpdateTask(
		context.Background(),
		appmcp.TaskRef{TaskID: upstreamTaskID},
		inputs,
	); err != nil {
		t.Fatalf("update task: %v", err)
	}

	params := taskParamsFrom(t, lastWireRequest(t, recorder))
	var responses map[string]any
	if err := json.Unmarshal(params["inputResponses"], &responses); err != nil {
		t.Fatalf("decode inputResponses: %v", err)
	}
	if _, ok := responses["q1"]; !ok {
		t.Fatalf("inputResponses = %v, want the client's answers forwarded", responses)
	}
}

// An upstream that sees no extension declaration may refuse to serve tasks/*, so
// the declaration is carried alongside whatever the client itself declared.
func TestModernUpstreamTaskCallDeclaresExtension(t *testing.T) {
	t.Parallel()
	upstream, recorder := recordingTaskUpstream(t, `{"taskId":"`+upstreamTaskID+`","status":"working"}`)
	ctx := appmcp.WithClientCapabilities(context.Background(), map[string]any{
		"elicitation": map[string]any{},
		appmcp.CapabilityKindExtensions: map[string]any{
			appmcp.MetaKeyTasksExtension: map[string]any{},
		},
	})

	if _, err := upstream.GetTask(ctx, appmcp.TaskRef{TaskID: upstreamTaskID}); err != nil {
		t.Fatalf("get task: %v", err)
	}

	meta := metaFromParams(t, taskParamsFrom(t, lastWireRequest(t, recorder)))
	var caps map[string]any
	if err := json.Unmarshal(meta[sdk.MetaKeyClientCapabilities], &caps); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if _, ok := caps["elicitation"]; !ok {
		t.Fatalf("capabilities = %v, want the client's own declaration kept", caps)
	}
	extensions, ok := caps[appmcp.CapabilityKindExtensions].(map[string]any)
	if !ok {
		t.Fatalf("capabilities = %v, want an extensions object", caps)
	}
	if _, ok := extensions[appmcp.MetaKeyTasksExtension]; !ok {
		t.Fatalf("extensions = %v, want the tasks extension declared", extensions)
	}
}

// A handle can contain characters that are unsafe in a header field. The
// northbound sentinel form is reused so the value survives the round trip.
func TestEncodeHeaderValueUsesSentinelForUnsafeValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "plain handle", value: "tg1k.c.payload.sig", want: "tg1k.c.payload.sig"},
		{name: "non ASCII", value: "café", want: "=?base64?Y2Fmw6k=?="},
		{name: "control character", value: "a\nb", want: "=?base64?YQpi?="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := encodeHeaderValue(tt.value); got != tt.want {
				t.Fatalf("encodeHeaderValue(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}
