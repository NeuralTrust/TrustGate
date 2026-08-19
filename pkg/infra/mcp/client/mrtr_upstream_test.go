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

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func recordingModernUpstream(t *testing.T) (*modernUpstream, *modernWireRecorder) {
	t.Helper()
	recorder := &modernWireRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		recorder.add(request)
		writeModernResult(t, w, request.id, `{"content":[]}`)
	}))
	t.Cleanup(srv.Close)
	return newTestModernUpstream(t, srv.URL+"/mcp", sharedHTTPTransport), recorder
}

func lastToolCallParams(t *testing.T, recorder *modernWireRecorder) map[string]json.RawMessage {
	t.Helper()
	requests := recorder.snapshot()
	if len(requests) == 0 {
		t.Fatal("no request reached the upstream")
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(requests[len(requests)-1].params, &params); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	return params
}

func metaFromParams(t *testing.T, params map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(params["_meta"], &meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	return meta
}

// A continuation call carries the client's answers and the upstream's own state,
// plus the capabilities the northbound client declared so the upstream knows
// what it may ask for next.
func TestModernUpstreamForwardsContinuationAndDeclaredCaps(t *testing.T) {
	t.Parallel()
	upstream, recorder := recordingModernUpstream(t)
	ctx := appmcp.WithClientCapabilities(context.Background(), map[string]any{
		"elicitation": map[string]any{},
	})

	if _, err := upstream.CallTool(ctx, appmcp.ToolCall{
		Name:           "tool-one",
		Arguments:      json.RawMessage(`{"value":42}`),
		InputResponses: json.RawMessage(`{"q1":{"action":"accept","content":{"city":"Madrid"}}}`),
		RequestState:   "upstream-state-1",
	}); err != nil {
		t.Fatalf("call tool: %v", err)
	}

	params := lastToolCallParams(t, recorder)
	var requestState string
	if err := json.Unmarshal(params["requestState"], &requestState); err != nil {
		t.Fatalf("decode requestState: %v", err)
	}
	if requestState != "upstream-state-1" {
		t.Fatalf("requestState = %q", requestState)
	}
	var responses map[string]any
	if err := json.Unmarshal(params["inputResponses"], &responses); err != nil {
		t.Fatalf("decode inputResponses: %v", err)
	}
	if _, ok := responses["q1"]; !ok {
		t.Fatalf("inputResponses = %v, want the client's answers forwarded", responses)
	}
	var caps map[string]any
	if err := json.Unmarshal(metaFromParams(t, params)[sdk.MetaKeyClientCapabilities], &caps); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if _, ok := caps["elicitation"]; !ok {
		t.Fatalf("capabilities = %v, want elicitation declared", caps)
	}
}

// An empty capability object tells the upstream nothing can be elicited, which
// would end the exchange. On a continuation with no declared caps the key is
// omitted instead of sent as `{}`.
func TestModernUpstreamOmitsEmptyCapsOnContinuation(t *testing.T) {
	t.Parallel()
	upstream, recorder := recordingModernUpstream(t)

	if _, err := upstream.CallTool(context.Background(), appmcp.ToolCall{
		Name:         "tool-one",
		RequestState: "upstream-state-1",
	}); err != nil {
		t.Fatalf("call tool: %v", err)
	}

	meta := metaFromParams(t, lastToolCallParams(t, recorder))
	if _, ok := meta[sdk.MetaKeyClientCapabilities]; ok {
		t.Fatalf("metadata = %v, want no client capabilities on a continuation", meta)
	}
}

// A first round still declares the empty capability set, keeping the existing
// stateless wire contract for plain calls unchanged.
func TestModernUpstreamKeepsEmptyCapsOnFirstRound(t *testing.T) {
	t.Parallel()
	upstream, recorder := recordingModernUpstream(t)

	if _, err := upstream.CallTool(context.Background(), appmcp.ToolCall{Name: "tool-one"}); err != nil {
		t.Fatalf("call tool: %v", err)
	}

	meta := metaFromParams(t, lastToolCallParams(t, recorder))
	if _, ok := meta[sdk.MetaKeyClientCapabilities]; !ok {
		t.Fatal("metadata must still declare client capabilities on a first round")
	}
}
