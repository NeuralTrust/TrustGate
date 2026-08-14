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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/version"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const testModernImplementationVersion = "9.8.7-test"

type modernWireRequest struct {
	httpMethod string
	headers    http.Header
	method     string
	id         json.RawMessage
	params     json.RawMessage
}

type modernWireRecorder struct {
	mu       sync.Mutex
	requests []modernWireRequest
}

func (r *modernWireRecorder) add(req modernWireRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
}

func (r *modernWireRecorder) snapshot() []modernWireRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]modernWireRequest(nil), r.requests...)
}

func decodeModernWireRequest(t *testing.T, r *http.Request) modernWireRequest {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return modernWireRequest{
		httpMethod: r.Method,
		headers:    r.Header.Clone(),
		method:     envelope.Method,
		id:         append(json.RawMessage(nil), envelope.ID...),
		params:     append(json.RawMessage(nil), envelope.Params...),
	}
}

func writeModernResult(t *testing.T, w http.ResponseWriter, id json.RawMessage, result string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if _, err := fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, id, result); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func writeModernRPCError(t *testing.T, w http.ResponseWriter, id json.RawMessage, code int64, message, data string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if _, err := fmt.Fprintf(
		w,
		`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q,"data":%s}}`,
		id,
		code,
		message,
		data,
	); err != nil {
		t.Errorf("write response: %v", err)
	}
}

func writeModernRPCErrorStatus(
	t *testing.T,
	w http.ResponseWriter,
	status int,
	id json.RawMessage,
	code int64,
	message string,
	data string,
) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeModernRPCError(t, w, id, code, message, data)
}

func modernCursor(t *testing.T, params json.RawMessage) string {
	t.Helper()
	var decoded struct {
		Cursor string `json:"cursor"`
	}
	if err := json.Unmarshal(params, &decoded); err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	return decoded.Cursor
}

func newTestModernUpstream(t *testing.T, endpoint string, transport http.RoundTripper) *modernUpstream {
	t.Helper()
	upstream, err := newModernUpstreamWithTransport(
		appmcp.Target{
			URL: endpoint,
			Headers: map[string]string{
				"Authorization": "Bearer target-token",
				"X-Tenant-ID":   "tenant-a",
			},
		},
		modernProtocolVersion,
		transport,
		testModernImplementationVersion,
	)
	if err != nil {
		t.Fatalf("new modern upstream: %v", err)
	}
	return upstream
}

func TestModernUpstreamOperationsAndStatelessWire(t *testing.T) {
	recorder := &modernWireRecorder{}
	page := make(map[string]int)
	var pageMu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		recorder.add(request)
		pageMu.Lock()
		page[request.method]++
		currentPage := page[request.method]
		pageMu.Unlock()

		switch request.method {
		case "tools/list":
			if currentPage == 1 {
				writeModernResult(t, w, request.id, `{"tools":[{"name":"tool-one","description":"first","inputSchema":{"type":"object","properties":{"input":{"type":"string","items":{"type":"integer"}}}},"outputSchema":{"type":"object","properties":{"nested":{"type":"array","items":{"type":"number"}}}},"_meta":{"owner":{"team":"runtime"}},"annotations":{"title":"Rich tool","readOnlyHint":true},"icons":[{"src":"https://example.com/tool.svg","mimeType":"image/svg+xml","sizes":["any"]}]}],"nextCursor":"tools-2"}`)
				return
			}
			writeModernResult(t, w, request.id, `{"tools":[{"name":"tool-two","description":"second"}]}`)
		case "prompts/list":
			if currentPage == 1 {
				writeModernResult(t, w, request.id, `{"prompts":[{"name":"prompt-one","_meta":{"owner":"runtime"},"icons":[{"src":"https://example.com/prompt.png","mimeType":"image/png","sizes":["48x48"]}]}],"nextCursor":"prompts-2"}`)
				return
			}
			writeModernResult(t, w, request.id, `{"prompts":[{"name":"prompt-two"}],"nextCursor":""}`)
		case "resources/list":
			if currentPage == 1 {
				writeModernResult(t, w, request.id, `{"resources":[{"name":"resource-one","uri":"file:///one","mimeType":"application/octet-stream","size":4096,"_meta":{"owner":"runtime"},"annotations":{"audience":["assistant"],"priority":0.75},"icons":[{"src":"https://example.com/resource.svg","mimeType":"image/svg+xml","sizes":["any"]}]}],"nextCursor":"resources-2"}`)
				return
			}
			writeModernResult(t, w, request.id, `{"resources":[{"name":"resource-two","uri":"file:///two"}]}`)
		case "resources/templates/list":
			if currentPage == 1 {
				writeModernResult(t, w, request.id, `{"resourceTemplates":[{"name":"template-one","uriTemplate":"file:///{name}"}],"nextCursor":"templates-2"}`)
				return
			}
			writeModernResult(t, w, request.id, `{"resourceTemplates":[{"name":"template-two","uriTemplate":"https://example.com/{id}"}]}`)
		case "resources/read":
			writeModernResult(t, w, request.id, `{"contents":[{"uri":"file:///one","mimeType":"application/octet-stream","blob":"AQID","_meta":{"checksum":"abc"}}],"future":{"preserved":"resource"}}`)
		case "prompts/get":
			writeModernResult(t, w, request.id, `{"description":"prompt","messages":[],"future":{"preserved":"prompt"}}`)
		case "tools/call":
			writeModernResult(t, w, request.id, `{"content":[{"type":"text","text":"ok"}],"structuredContent":{"nested":{"values":[1,2,3]}},"future":{"preserved":"tool"}}`)
		default:
			t.Errorf("unexpected method %q", request.method)
			writeModernRPCError(t, w, request.id, -32601, "Method not found", `null`)
		}
	}))
	t.Cleanup(srv.Close)

	upstream, err := newModernUpstream(
		appmcp.Target{
			URL: srv.URL + "/mcp",
			Headers: map[string]string{
				"Authorization": "Bearer target-token",
				"X-Tenant-ID":   "tenant-a",
			},
		},
		modernProtocolVersion,
	)
	if err != nil {
		t.Fatalf("new modern upstream: %v", err)
	}
	if !upstream.SupportsResources() || !upstream.SupportsPrompts() {
		t.Fatal("modern upstream must not infer unsupported capabilities")
	}

	tools, err := upstream.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 2 || tools[0].Name != "tool-one" || tools[1].Name != "tool-two" {
		t.Fatalf("tools = %+v", tools)
	}
	listToolRaw, err := json.Marshal(tools[0])
	if err != nil {
		t.Fatalf("marshal tool: %v", err)
	}
	assertJSONContains(t, listToolRaw, map[string]any{
		"name":         "tool-one",
		"description":  "first",
		"inputSchema":  map[string]any{"type": "object", "properties": map[string]any{"input": map[string]any{"type": "string", "items": map[string]any{"type": "integer"}}}},
		"outputSchema": map[string]any{"type": "object", "properties": map[string]any{"nested": map[string]any{"type": "array", "items": map[string]any{"type": "number"}}}},
		"_meta":        map[string]any{"owner": map[string]any{"team": "runtime"}},
		"annotations":  map[string]any{"title": "Rich tool", "readOnlyHint": true},
		"icons":        []any{map[string]any{"src": "https://example.com/tool.svg", "mimeType": "image/svg+xml", "sizes": []any{"any"}}},
	})

	prompts, err := upstream.ListPrompts(context.Background())
	if err != nil {
		t.Fatalf("list prompts: %v", err)
	}
	if len(prompts) != 2 || prompts[0].Name != "prompt-one" || prompts[1].Name != "prompt-two" {
		t.Fatalf("prompts = %+v", prompts)
	}
	listPromptRaw, err := json.Marshal(prompts[0])
	if err != nil {
		t.Fatalf("marshal prompt: %v", err)
	}
	assertJSONContains(t, listPromptRaw, map[string]any{
		"name":  "prompt-one",
		"_meta": map[string]any{"owner": "runtime"},
		"icons": []any{map[string]any{"src": "https://example.com/prompt.png", "mimeType": "image/png", "sizes": []any{"48x48"}}},
	})

	resources, err := upstream.ListResources(context.Background())
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 2 || resources[0].URI != "file:///one" || resources[1].URI != "file:///two" {
		t.Fatalf("resources = %+v", resources)
	}
	listResourceRaw, err := json.Marshal(resources[0])
	if err != nil {
		t.Fatalf("marshal resource: %v", err)
	}
	assertJSONContains(t, listResourceRaw, map[string]any{
		"name":     "resource-one",
		"uri":      "file:///one",
		"mimeType": "application/octet-stream",
		"size":     float64(4096),
		"_meta":    map[string]any{"owner": "runtime"},
		"annotations": map[string]any{
			"audience": []any{"assistant"},
			"priority": float64(0.75),
		},
		"icons": []any{map[string]any{"src": "https://example.com/resource.svg", "mimeType": "image/svg+xml", "sizes": []any{"any"}}},
	})

	templates, err := upstream.ListResourceTemplates(context.Background())
	if err != nil {
		t.Fatalf("list resource templates: %v", err)
	}
	if len(templates) != 2 ||
		templates[0].URITemplate != "file:///{name}" ||
		templates[1].URITemplate != "https://example.com/{id}" {
		t.Fatalf("resource templates = %+v", templates)
	}
	listTemplateRaw, err := json.Marshal(templates[0])
	if err != nil {
		t.Fatalf("marshal resource template: %v", err)
	}
	assertJSONEqual(t, `{"name":"template-one","uriTemplate":"file:///{name}"}`, listTemplateRaw)

	readRaw, err := upstream.ReadResource(context.Background(), "file:///one")
	if err != nil {
		t.Fatalf("read resource: %v", err)
	}
	assertJSONEqual(
		t,
		`{"contents":[{"uri":"file:///one","mimeType":"application/octet-stream","blob":"AQID","_meta":{"checksum":"abc"}}],"future":{"preserved":"resource"}}`,
		readRaw,
	)

	promptRaw, err := upstream.GetPrompt(context.Background(), "prompt-one", map[string]string{"subject": "world"})
	if err != nil {
		t.Fatalf("get prompt: %v", err)
	}
	assertJSONEqual(
		t,
		`{"description":"prompt","messages":[],"future":{"preserved":"prompt"}}`,
		promptRaw,
	)

	toolRaw, err := upstream.CallTool(context.Background(), "tool-one", json.RawMessage(`{"value":42}`))
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	assertJSONEqual(
		t,
		`{"content":[{"type":"text","text":"ok"}],"structuredContent":{"nested":{"values":[1,2,3]}},"future":{"preserved":"tool"}}`,
		toolRaw,
	)

	beforeClose := len(recorder.snapshot())
	upstream.Close(context.Background())
	upstream.Close(context.Background())
	if afterClose := len(recorder.snapshot()); afterClose != beforeClose {
		t.Fatalf("Close emitted %d requests", afterClose-beforeClose)
	}

	requests := recorder.snapshot()
	if len(requests) != 11 {
		t.Fatalf("wire request count = %d, want 11", len(requests))
	}
	wantNames := map[string]string{
		"resources/read": "file:///one",
		"prompts/get":    "prompt-one",
		"tools/call":     "tool-one",
	}
	for _, request := range requests {
		if request.httpMethod != http.MethodPost {
			t.Errorf("%s used HTTP %s", request.method, request.httpMethod)
		}
		if request.headers.Get("Mcp-Protocol-Version") != modernProtocolVersion {
			t.Errorf("%s protocol header = %q", request.method, request.headers.Get("Mcp-Protocol-Version"))
		}
		if request.headers.Get("Mcp-Method") != request.method {
			t.Errorf("%s method header = %q", request.method, request.headers.Get("Mcp-Method"))
		}
		if request.headers.Get("Mcp-Name") != wantNames[request.method] {
			t.Errorf("%s name header = %q", request.method, request.headers.Get("Mcp-Name"))
		}
		if request.headers.Get("Mcp-Session-Id") != "" {
			t.Errorf("%s sent session ID", request.method)
		}
		if request.headers.Get("User-Agent") != "trustgate/"+version.Version {
			t.Errorf("%s user agent = %q", request.method, request.headers.Get("User-Agent"))
		}
		if request.headers.Get("Authorization") != "Bearer target-token" ||
			request.headers.Get("X-Tenant-ID") != "tenant-a" {
			t.Errorf("%s lost target headers", request.method)
		}
		assertModernMetadata(t, request.params, version.Version)
		switch request.method {
		case "tools/list", "prompts/list", "resources/list", "resources/templates/list":
			cursor := modernCursor(t, request.params)
			if pageForMethod(requests, request.method, request.id) == 1 && cursor != "" {
				t.Errorf("%s first cursor = %q", request.method, cursor)
			}
		}
	}
	assertModernOperationParams(t, requests)
}

func pageForMethod(requests []modernWireRequest, method string, id json.RawMessage) int {
	page := 0
	for _, request := range requests {
		if request.method == method {
			page++
		}
		if request.method == method && string(request.id) == string(id) {
			return page
		}
	}
	return 0
}

func assertModernMetadata(t *testing.T, params json.RawMessage, implementationVersion string) {
	t.Helper()
	var decoded struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &decoded); err != nil {
		t.Fatalf("decode params metadata: %v", err)
	}
	if len(decoded.Meta) != 3 {
		t.Fatalf("metadata = %s, want exactly three fields", decoded.Meta)
	}
	var protocolVersion string
	if err := json.Unmarshal(decoded.Meta[sdk.MetaKeyProtocolVersion], &protocolVersion); err != nil {
		t.Fatalf("decode protocol version: %v", err)
	}
	if protocolVersion != modernProtocolVersion {
		t.Fatalf("metadata protocol version = %q", protocolVersion)
	}
	var info sdk.Implementation
	if err := json.Unmarshal(decoded.Meta[sdk.MetaKeyClientInfo], &info); err != nil {
		t.Fatalf("decode client info: %v", err)
	}
	if info.Name != clientName || info.Version != implementationVersion {
		t.Fatalf("client info = %+v", info)
	}
	var capabilities map[string]any
	if err := json.Unmarshal(decoded.Meta[sdk.MetaKeyClientCapabilities], &capabilities); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if len(capabilities) != 0 {
		t.Fatalf("client capabilities = %+v, want empty", capabilities)
	}
}

func assertModernOperationParams(t *testing.T, requests []modernWireRequest) {
	t.Helper()
	for _, request := range requests {
		switch request.method {
		case "resources/read":
			var params sdk.ReadResourceParams
			if err := json.Unmarshal(request.params, &params); err != nil {
				t.Fatalf("decode resources/read params: %v", err)
			}
			if params.URI != "file:///one" {
				t.Fatalf("read URI = %q", params.URI)
			}
		case "prompts/get":
			var params sdk.GetPromptParams
			if err := json.Unmarshal(request.params, &params); err != nil {
				t.Fatalf("decode prompts/get params: %v", err)
			}
			if params.Name != "prompt-one" || params.Arguments["subject"] != "world" {
				t.Fatalf("get prompt params = %+v", params)
			}
		case "tools/call":
			var params sdk.CallToolParamsRaw
			if err := json.Unmarshal(request.params, &params); err != nil {
				t.Fatalf("decode tools/call params: %v", err)
			}
			if params.Name != "tool-one" {
				t.Fatalf("tool name = %q", params.Name)
			}
			assertJSONEqual(t, `{"value":42}`, params.Arguments)
		}
	}
}

func assertJSONEqual(t *testing.T, want string, got []byte) {
	t.Helper()
	var wantValue any
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("decode expected JSON: %v", err)
	}
	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode actual JSON %q: %v", got, err)
	}
	wantJSON, err := json.Marshal(wantValue)
	if err != nil {
		t.Fatalf("encode expected JSON: %v", err)
	}
	gotJSON, err := json.Marshal(gotValue)
	if err != nil {
		t.Fatalf("encode actual JSON: %v", err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("JSON = %s, want %s", gotJSON, wantJSON)
	}
}

func assertJSONContains(t *testing.T, got []byte, fields map[string]any) {
	t.Helper()
	var actual map[string]any
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatalf("decode actual object: %v", err)
	}
	for key, value := range fields {
		gotValue, ok := actual[key]
		if !ok {
			t.Fatalf("field %q missing from %s", key, got)
		}
		if !jsonContains(gotValue, value) {
			t.Fatalf("field %q = %#v, want it to contain %#v", key, gotValue, value)
		}
	}
}

func jsonContains(actual any, expected any) bool {
	switch expected := expected.(type) {
	case map[string]any:
		actual, ok := actual.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range expected {
			got, exists := actual[key]
			if !exists || !jsonContains(got, value) {
				return false
			}
		}
		return true
	case []any:
		actual, ok := actual.([]any)
		if !ok || len(actual) != len(expected) {
			return false
		}
		for index := range expected {
			if !jsonContains(actual[index], expected[index]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(actual, expected)
	}
}

func TestModernUpstreamPaginationStopsOnAbsentOrEmptyCursor(t *testing.T) {
	tests := []struct {
		name       string
		nextCursor string
	}{
		{name: "absent"},
		{name: "empty", nextCursor: `,"nextCursor":""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := decodeModernWireRequest(t, r)
				calls.Add(1)
				writeModernResult(t, w, request.id, `{"tools":[{"name":"one"}]`+tt.nextCursor+`}`)
			}))
			t.Cleanup(srv.Close)

			upstream := newTestModernUpstream(t, srv.URL, sharedHTTPTransport)
			tools, err := upstream.ListTools(context.Background())
			if err != nil {
				t.Fatalf("list tools: %v", err)
			}
			if len(tools) != 1 || calls.Load() != 1 {
				t.Fatalf("tools = %+v, calls = %d", tools, calls.Load())
			}
		})
	}
}

func TestModernUpstreamReadsUntilMatchingResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := fmt.Fprintf(
			w,
			"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n"+
				"data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"tools\":[{\"name\":\"one\"}]}}\n\n",
			request.id,
		); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	upstream := newTestModernUpstream(t, srv.URL, sharedHTTPTransport)
	tools, err := upstream.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "one" {
		t.Fatalf("tools = %+v", tools)
	}
}

func TestModernUpstreamPaginationRejectsRepeatedAndCyclicCursors(t *testing.T) {
	tests := []struct {
		name        string
		nextCursors []string
		wantCalls   int64
	}{
		{name: "repeated", nextCursors: []string{"a", "a"}, wantCalls: 2},
		{name: "cyclic", nextCursors: []string{"a", "b", "a"}, wantCalls: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := decodeModernWireRequest(t, r)
				call := int(calls.Add(1)) - 1
				writeModernResult(
					t,
					w,
					request.id,
					fmt.Sprintf(`{"tools":[{"name":"tool-%d"}],"nextCursor":%q}`, call, tt.nextCursors[call]),
				)
			}))
			t.Cleanup(srv.Close)

			upstream := newTestModernUpstream(t, srv.URL, sharedHTTPTransport)
			_, err := upstream.ListTools(context.Background())
			if !errors.Is(err, errModernCursorCycle) {
				t.Fatalf("error = %v, want cursor cycle", err)
			}
			if calls.Load() != tt.wantCalls {
				t.Fatalf("calls = %d, want %d", calls.Load(), tt.wantCalls)
			}
		})
	}
}

func TestModernUpstreamPaginationHasPageLimit(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		call := calls.Add(1)
		writeModernResult(
			t,
			w,
			request.id,
			fmt.Sprintf(`{"tools":[{"name":"tool-%d"}],"nextCursor":"page-%d"}`, call, call+1),
		)
	}))
	t.Cleanup(srv.Close)

	upstream := newTestModernUpstream(t, srv.URL, sharedHTTPTransport)
	_, err := upstream.ListTools(context.Background())
	if !errors.Is(err, errModernPageLimit) {
		t.Fatalf("error = %v, want page limit", err)
	}
	if calls.Load() != int64(maxModernPages) {
		t.Fatalf("calls = %d, want %d", calls.Load(), maxModernPages)
	}
}

func TestModernUpstreamPaginationAcceptsFinalPageAtLimit(t *testing.T) {
	calls := 0
	items, err := paginateModern(context.Background(), "test/list", func(context.Context, string) ([]int, string, error) {
		calls++
		next := ""
		if calls < maxModernPages {
			next = fmt.Sprintf("page-%d", calls+1)
		}
		return []int{calls}, next, nil
	})
	if err != nil {
		t.Fatalf("paginate: %v", err)
	}
	if calls != maxModernPages || len(items) != maxModernPages {
		t.Fatalf("calls = %d, items = %d, want %d", calls, len(items), maxModernPages)
	}
}

func TestModernUpstreamPaginationHasAggregateItemLimit(t *testing.T) {
	tests := []struct {
		name      string
		pageSizes []int
		wantErr   bool
	}{
		{name: "inclusive boundary", pageSizes: []int{6000, 4000}},
		{name: "overflow", pageSizes: []int{6000, 4001}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pageNumber := 0
			items, err := paginateModern(context.Background(), "test/list", func(context.Context, string) ([]int, string, error) {
				size := tt.pageSizes[pageNumber]
				pageNumber++
				next := ""
				if pageNumber < len(tt.pageSizes) {
					next = fmt.Sprintf("page-%d", pageNumber)
				}
				return make([]int, size), next, nil
			})
			if tt.wantErr {
				if !errors.Is(err, errModernItemLimit) {
					t.Fatalf("error = %v, want item limit", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("paginate: %v", err)
			}
			if len(items) != maxModernItems {
				t.Fatalf("items = %d, want %d", len(items), maxModernItems)
			}
		})
	}
}

func TestModernUpstreamCancellationStopsIOWithoutRetry(t *testing.T) {
	started := make(chan struct{})
	var calls atomic.Int64
	transport := modernRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})

	upstream := newTestModernUpstream(t, "https://mcp.example.test", transport)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	_, err := upstream.ListTools(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want one", calls.Load())
	}
}

type modernRoundTripFunc func(*http.Request) (*http.Response, error)

func (f modernRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type failingReadCloser struct {
	err    error
	closed atomic.Bool
}

func (r *failingReadCloser) Read([]byte) (int, error) {
	return 0, r.err
}

func (r *failingReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

type trackedReadCloser struct {
	reader io.Reader
	closed atomic.Bool
	reads  atomic.Int64
}

func (r *trackedReadCloser) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.reads.Add(int64(n))
	return n, err
}

func (r *trackedReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

func TestModernUpstreamSanitizesTransportAndReadErrors(t *testing.T) {
	tests := []struct {
		name      string
		transport func(*failingReadCloser) http.RoundTripper
	}{
		{
			name: "transport",
			transport: func(*failingReadCloser) http.RoundTripper {
				return modernRoundTripFunc(func(*http.Request) (*http.Response, error) {
					return nil, errors.New("transport-secret-sentinel")
				})
			},
		},
		{
			name: "read",
			transport: func(body *failingReadCloser) http.RoundTripper {
				return modernRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:       body,
						Request:    req,
					}, nil
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &failingReadCloser{err: errors.New("read-secret-sentinel")}
			upstream := newTestModernUpstream(t, "https://mcp.example.test/private?token=url-secret", tt.transport(body))
			_, err := upstream.ListTools(context.Background())
			if !errors.Is(err, appmcp.ErrUnreachable) {
				t.Fatalf("error = %v, want ErrUnreachable", err)
			}
			for _, secret := range []string{"transport-secret-sentinel", "read-secret-sentinel", "url-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error exposed %q: %v", secret, err)
				}
			}
			if tt.name == "read" && !body.closed.Load() {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestModernUpstreamPreservesRPCBusinessError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		writeModernRPCError(t, w, request.id, -32099, "business failure", `{"retryable":false}`)
	}))
	t.Cleanup(srv.Close)

	upstream := newTestModernUpstream(t, srv.URL, sharedHTTPTransport)
	_, err := upstream.CallTool(context.Background(), "tool", json.RawMessage(`{}`))
	var rpcErr *appmcp.RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("error = %v, want RPCError", err)
	}
	if rpcErr.Code != -32099 || rpcErr.Message != "business failure" {
		t.Fatalf("RPC error = %+v", rpcErr)
	}
	assertJSONEqual(t, `{"retryable":false}`, rpcErr.Data)
}

func TestModernUpstreamPreservesRPCErrorFromHTTP400And404(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := decodeModernWireRequest(t, r)
				writeModernRPCErrorStatus(
					t,
					w,
					status,
					request.id,
					-32099,
					"business failure",
					`{"status":"rejected"}`,
				)
			}))
			t.Cleanup(srv.Close)

			tracker := &countingResponseRoundTripper{transport: sharedHTTPTransport}
			upstream := newTestModernUpstream(t, srv.URL, tracker)
			_, err := upstream.CallTool(context.Background(), "tool", json.RawMessage(`{}`))
			var rpcErr *appmcp.RPCError
			if !errors.As(err, &rpcErr) {
				t.Fatalf("error = %v, want RPCError", err)
			}
			if rpcErr.Code != -32099 || rpcErr.Message != "business failure" {
				t.Fatalf("RPC error = %+v", rpcErr)
			}
			assertJSONEqual(t, `{"status":"rejected"}`, rpcErr.Data)
			if errors.Is(err, sdk.ErrSessionMissing) {
				t.Fatalf("HTTP %d became ErrSessionMissing", status)
			}
			if tracker.closed.Load() != 1 {
				t.Fatalf("closed original bodies = %d, want one", tracker.closed.Load())
			}
		})
	}
}

func TestModernRoundTripperStrictErrorNormalization(t *testing.T) {
	tests := []struct {
		name             string
		requestID        string
		requestType      string
		responseType     string
		omitResponseType bool
		response         string
		wantNormalize    bool
	}{
		{
			name:          "valid string ID",
			requestID:     `"request"`,
			requestType:   "application/json",
			response:      `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":"failure","data":{"reason":"bounded"}}}`,
			wantNormalize: true,
		},
		{
			name:          "valid charset parameter",
			requestID:     `"request"`,
			requestType:   "application/json; charset=utf-8",
			responseType:  "application/json; charset=utf-8",
			response:      `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":"failure"}}`,
			wantNormalize: true,
		},
		{
			name:          "valid numeric ID",
			requestID:     `1`,
			requestType:   "application/json",
			response:      `{"jsonrpc":"2.0","id":1,"error":{"code":9223372036854775807,"message":"failure"}}`,
			wantNormalize: true,
		},
		{
			name:         "text response content type",
			requestID:    `"request"`,
			requestType:  "application/json",
			responseType: "text/plain",
			response:     `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:             "missing response content type",
			requestID:        `"request"`,
			requestType:      "application/json",
			omitResponseType: true,
			response:         `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:         "malformed response content type",
			requestID:    `"request"`,
			requestType:  "application/json",
			responseType: `application/json; charset="`,
			response:     `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "wrong request content type",
			requestID:   `"request"`,
			requestType: "text/plain",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "malformed request content type",
			requestID:   `"request"`,
			requestType: `application/json; charset="`,
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "malformed JSON",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":`,
		},
		{
			name:        "batch",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `[{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":"failure"}}]`,
		},
		{
			name:        "missing jsonrpc",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "wrong jsonrpc",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"1.0","id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "null jsonrpc",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":null,"id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "missing ID",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "null ID",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":null,"error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "boolean ID",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":true,"error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "different ID",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"other","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "number versus string ID",
			requestID:   `1`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"1","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "numeric bytes differ",
			requestID:   `1`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":1.0,"error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "result only",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","result":{}}`,
		},
		{
			name:        "result and error",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","result":null,"error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "method and error",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","method":"tools/list","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "missing error",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request"}`,
		},
		{
			name:        "null error",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":null}`,
		},
		{
			name:        "array error",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":[]}`,
		},
		{
			name:        "missing code",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"message":"failure"}}`,
		},
		{
			name:        "null code",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":null,"message":"failure"}}`,
		},
		{
			name:        "string code",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":"-32099","message":"failure"}}`,
		},
		{
			name:        "fractional code",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":-32099.5,"message":"failure"}}`,
		},
		{
			name:        "code overflow",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":9223372036854775808,"message":"failure"}}`,
		},
		{
			name:        "missing message",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":-32099}}`,
		},
		{
			name:        "null message",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":null}}`,
		},
		{
			name:        "numeric message",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"message":7}}`,
		},
		{
			name:        "duplicate envelope field",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","id":"request","error":{"code":-32099,"message":"failure"}}`,
		},
		{
			name:        "duplicate error field",
			requestID:   `"request"`,
			requestType: "application/json",
			response:    `{"jsonrpc":"2.0","id":"request","error":{"code":-32099,"code":-32098,"message":"failure"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestBody := fmt.Sprintf(
				`{"jsonrpc":"2.0","id":%s,"method":"tools/list","params":{}}`,
				tt.requestID,
			)
			req, err := http.NewRequest(
				http.MethodPost,
				"https://mcp.example.test",
				bytes.NewReader([]byte(requestBody)),
			)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", tt.requestType)

			var closed atomic.Int64
			transport := &modernRoundTripper{
				transport: modernRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					responseType := tt.responseType
					if responseType == "" {
						responseType = "application/json"
					}
					headers := http.Header{
						"Connection":        []string{"X-Hop"},
						"Content-Encoding":  []string{"gzip"},
						"Content-Length":    []string{"999"},
						"Content-MD5":       []string{"digest"},
						"Trailer":           []string{"X-Trailer"},
						"Transfer-Encoding": []string{"chunked"},
						"X-Hop":             []string{"remove-me"},
					}
					if !tt.omitResponseType {
						headers.Set("Content-Type", responseType)
					}
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Status:     "400 Bad Request",
						Header:     headers,
						Body: &countingResponseBody{
							ReadCloser: io.NopCloser(strings.NewReader(tt.response)),
							closed:     &closed,
						},
						ContentLength:    int64(len(tt.response)),
						TransferEncoding: []string{"chunked"},
						Trailer:          http.Header{"X-Trailer": []string{"value"}},
						Request:          req,
					}, nil
				}),
				protocolVersion:       modernProtocolVersion,
				implementationVersion: testModernImplementationVersion,
			}

			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read restored body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatalf("close restored body: %v", err)
			}
			if string(body) != tt.response {
				t.Fatalf("body = %q, want %q", body, tt.response)
			}
			if closed.Load() != 1 {
				t.Fatalf("original body closes = %d, want one", closed.Load())
			}
			if tt.wantNormalize {
				if resp.StatusCode != http.StatusOK || resp.Status != "200 OK" {
					t.Fatalf("status = %d %q, want 200 OK", resp.StatusCode, resp.Status)
				}
				if resp.Header.Get("Content-Type") != "application/json" {
					t.Fatalf("content type = %q", resp.Header.Get("Content-Type"))
				}
				if resp.Header.Get("Content-Length") != strconv.Itoa(len(tt.response)) {
					t.Fatalf("content length = %q", resp.Header.Get("Content-Length"))
				}
				for _, header := range []string{
					"Connection",
					"Content-Encoding",
					"Content-MD5",
					"Trailer",
					"Transfer-Encoding",
					"X-Hop",
				} {
					if resp.Header.Get(header) != "" {
						t.Fatalf("header %s was retained", header)
					}
				}
				if len(resp.TransferEncoding) != 0 || len(resp.Trailer) != 0 {
					t.Fatalf("framing metadata retained: transfer=%v trailer=%v", resp.TransferEncoding, resp.Trailer)
				}
				return
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want original 400", resp.StatusCode)
			}
		})
	}
}

func TestModernUpstreamDoesNotNormalizeInvalidHTTPErrorResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   func(json.RawMessage) string
	}{
		{
			name:   "400 malformed",
			status: http.StatusBadRequest,
			body:   func(json.RawMessage) string { return `{"jsonrpc":` },
		},
		{
			name:   "404 ID mismatch",
			status: http.StatusNotFound,
			body: func(json.RawMessage) string {
				return `{"jsonrpc":"2.0","id":"other","error":{"code":-32099,"message":"wrong"}}`
			},
		},
		{
			name:   "400 result",
			status: http.StatusBadRequest,
			body: func(id json.RawMessage) string {
				return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"unexpected":true}}`, id)
			},
		},
		{
			name:   "404 batch",
			status: http.StatusNotFound,
			body: func(id json.RawMessage) string {
				return fmt.Sprintf(`[{"jsonrpc":"2.0","id":%s,"error":{"code":-32099,"message":"batched"}}]`, id)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := decodeModernWireRequest(t, r)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				if _, err := io.WriteString(w, tt.body(request.id)); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			t.Cleanup(srv.Close)

			tracker := &countingResponseRoundTripper{transport: sharedHTTPTransport}
			upstream := newTestModernUpstream(t, srv.URL, tracker)
			_, err := upstream.CallTool(context.Background(), "tool", json.RawMessage(`{}`))
			if !errors.Is(err, appmcp.ErrUnreachable) {
				t.Fatalf("error = %v, want ErrUnreachable", err)
			}
			var rpcErr *appmcp.RPCError
			if errors.As(err, &rpcErr) {
				t.Fatalf("response was normalized to RPCError: %+v", rpcErr)
			}
			if tt.status == http.StatusNotFound && !errors.Is(err, sdk.ErrSessionMissing) {
				t.Fatalf("HTTP 404 error = %v, want original ErrSessionMissing path", err)
			}
			if tracker.closed.Load() != 1 {
				t.Fatalf("closed original bodies = %d, want one", tracker.closed.Load())
			}
		})
	}
}

func TestModernUpstreamMapsMethodNotFoundAndPreservesRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		writeModernRPCError(t, w, request.id, -32601, "Method not found", `{"method":"resources/read"}`)
	}))
	t.Cleanup(srv.Close)

	upstream := newTestModernUpstream(t, srv.URL, sharedHTTPTransport)
	_, err := upstream.ReadResource(context.Background(), "file:///missing")
	if !errors.Is(err, appmcp.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
	var rpcErr *appmcp.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != -32601 {
		t.Fatalf("error = %v, want preserved -32601 RPCError", err)
	}
}

func TestModernUpstreamRejectsSessionResponseAndClosesBody(t *testing.T) {
	body := &failingReadCloser{err: io.EOF}
	var calls atomic.Int64
	transport := modernRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"application/json"},
				"Mcp-Session-Id": []string{"session-secret-sentinel"},
			},
			Body:    body,
			Request: req,
		}, nil
	})
	upstream := newTestModernUpstream(t, "https://mcp.example.test", transport)

	_, err := upstream.ListTools(context.Background())
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if strings.Contains(err.Error(), "session-secret-sentinel") {
		t.Fatalf("error exposed session ID: %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("response body was not closed")
	}
	upstream.Close(context.Background())
	upstream.Close(context.Background())
	if calls.Load() != 1 {
		t.Fatalf("wire calls = %d, want one POST and no DELETE", calls.Load())
	}
}

func TestModernUpstreamBoundsResponseBodies(t *testing.T) {
	tests := []struct {
		name          string
		contentLength int64
		wantReads     bool
	}{
		{name: "known length", contentLength: maxModernResponseBodyBytes + 1},
		{name: "unknown length", contentLength: -1, wantReads: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &trackedReadCloser{
				reader: bytes.NewReader(bytes.Repeat([]byte("x"), int(maxModernResponseBodyBytes+1))),
			}
			transport := modernRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Header:        http.Header{"Content-Type": []string{"application/json"}},
					Body:          body,
					ContentLength: tt.contentLength,
					Request:       req,
				}, nil
			})
			upstream := newTestModernUpstream(t, "https://mcp.example.test", transport)

			_, err := upstream.ListTools(context.Background())
			if !errors.Is(err, appmcp.ErrUnreachable) {
				t.Fatalf("error = %v, want ErrUnreachable", err)
			}
			if strings.Contains(err.Error(), strings.Repeat("x", 32)) {
				t.Fatalf("error exposed response content: %v", err)
			}
			if !body.closed.Load() {
				t.Fatal("response body was not closed")
			}
			if tt.wantReads && body.reads.Load() != maxModernResponseBodyBytes+1 {
				t.Fatalf("read bytes = %d, want %d", body.reads.Load(), maxModernResponseBodyBytes+1)
			}
			if !tt.wantReads && body.reads.Load() != 0 {
				t.Fatalf("read bytes = %d, want zero", body.reads.Load())
			}
		})
	}
}

func exactModernListToolsResponse(t *testing.T, id json.RawMessage, size int) []byte {
	t.Helper()
	prefix := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":[],"padding":"`, id))
	suffix := []byte(`"}}`)
	paddingSize := size - len(prefix) - len(suffix)
	if paddingSize < 0 {
		t.Fatalf("response framing exceeds requested size %d", size)
	}
	body := make([]byte, 0, size)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("x"), paddingSize)...)
	body = append(body, suffix...)
	if len(body) != size {
		t.Fatalf("response size = %d, want %d", len(body), size)
	}
	return body
}

func TestModernUpstreamAcceptsResponseBodyAtExactLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		body := exactModernListToolsResponse(t, request.id, int(maxModernResponseBodyBytes))
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	tracker := &countingResponseRoundTripper{transport: sharedHTTPTransport}
	upstream := newTestModernUpstream(t, srv.URL, tracker)
	tools, err := upstream.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 0 {
		t.Fatalf("tools = %+v, want empty", tools)
	}
	if tracker.closed.Load() != 1 {
		t.Fatalf("closed bodies = %d, want one", tracker.closed.Load())
	}
}

func TestModernUpstreamRejectsChunkedGzipExpansionBeyondLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer does not support flushing")
			return
		}
		flusher.Flush()
		writer := gzip.NewWriter(w)
		if _, err := writer.Write(bytes.Repeat([]byte("x"), int(maxModernResponseBodyBytes+1))); err != nil {
			t.Errorf("write gzip response: %v", err)
			return
		}
		if err := writer.Close(); err != nil {
			t.Errorf("close gzip response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	tracker := &countingResponseRoundTripper{transport: sharedHTTPTransport}
	upstream := newTestModernUpstream(t, srv.URL+"/private?token=url-secret", tracker)
	_, err := upstream.ListTools(context.Background())
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	for _, secret := range []string{"url-secret", strings.Repeat("x", 32)} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error exposed %q: %v", secret, err)
		}
	}
	if tracker.closed.Load() != 1 {
		t.Fatalf("closed bodies = %d, want one", tracker.closed.Load())
	}
}

type scriptedModernConnection struct {
	messages  []jsonrpc.Message
	readIndex int
	writes    int
	closed    int
}

func (c *scriptedModernConnection) Read(context.Context) (jsonrpc.Message, error) {
	if c.readIndex >= len(c.messages) {
		return nil, io.EOF
	}
	message := c.messages[c.readIndex]
	c.readIndex++
	return message, nil
}

func (c *scriptedModernConnection) Write(context.Context, jsonrpc.Message) error {
	c.writes++
	return nil
}

func (c *scriptedModernConnection) Close() error {
	c.closed++
	return nil
}

func (c *scriptedModernConnection) SessionID() string {
	return ""
}

func mustModernID(t *testing.T, value any) jsonrpc.ID {
	t.Helper()
	id, err := jsonrpc.MakeID(value)
	if err != nil {
		t.Fatalf("make ID: %v", err)
	}
	return id
}

func TestModernUpstreamExchangeRejectsUnexpectedMessages(t *testing.T) {
	upstream := &modernUpstream{origin: "https://mcp.example.test:443"}
	requestID := mustModernID(t, "request")
	request := &jsonrpc.Request{ID: requestID, Method: "tools/list"}

	t.Run("ID mismatch", func(t *testing.T) {
		conn := &scriptedModernConnection{messages: []jsonrpc.Message{
			&jsonrpc.Response{ID: mustModernID(t, "other"), Result: json.RawMessage(`{}`)},
		}}
		_, err := upstream.exchange(context.Background(), conn, request, requestID)
		if !errors.Is(err, errModernResponseID) {
			t.Fatalf("error = %v, want response ID mismatch", err)
		}
	})

	t.Run("inbound server call", func(t *testing.T) {
		conn := &scriptedModernConnection{messages: []jsonrpc.Message{
			&jsonrpc.Request{ID: mustModernID(t, "server"), Method: "sampling/createMessage"},
		}}
		_, err := upstream.exchange(context.Background(), conn, request, requestID)
		if !errors.Is(err, errModernMessageType) {
			t.Fatalf("error = %v, want unexpected message type", err)
		}
	})

	t.Run("spurious message limit", func(t *testing.T) {
		messages := make([]jsonrpc.Message, maxModernResponseMessages+1)
		for index := 0; index < maxModernResponseMessages; index++ {
			messages[index] = &jsonrpc.Request{Method: "notifications/progress"}
		}
		messages[maxModernResponseMessages] = &jsonrpc.Response{
			ID:     requestID,
			Result: json.RawMessage(`{"tools":[]}`),
		}
		conn := &scriptedModernConnection{messages: messages}
		_, err := upstream.exchange(context.Background(), conn, request, requestID)
		if !errors.Is(err, errModernResponseLimit) {
			t.Fatalf("error = %v, want response message limit", err)
		}
		if conn.readIndex != maxModernResponseMessages {
			t.Fatalf("reads = %d, want %d", conn.readIndex, maxModernResponseMessages)
		}
	})

	t.Run("matching response at inclusive limit", func(t *testing.T) {
		messages := make([]jsonrpc.Message, maxModernResponseMessages)
		for index := 0; index < maxModernResponseMessages-1; index++ {
			messages[index] = &jsonrpc.Request{Method: "notifications/progress"}
		}
		messages[maxModernResponseMessages-1] = &jsonrpc.Response{
			ID:     requestID,
			Result: json.RawMessage(`{"tools":[]}`),
		}
		conn := &scriptedModernConnection{messages: messages}
		result, err := upstream.exchange(context.Background(), conn, request, requestID)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		assertJSONEqual(t, `{"tools":[]}`, result)
		if conn.readIndex != maxModernResponseMessages {
			t.Fatalf("reads = %d, want %d", conn.readIndex, maxModernResponseMessages)
		}
	})
}

type countingResponseRoundTripper struct {
	transport http.RoundTripper
	closed    atomic.Int64
}

func (t *countingResponseRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &countingResponseBody{ReadCloser: resp.Body, closed: &t.closed}
	return resp, nil
}

type countingResponseBody struct {
	io.ReadCloser
	closed *atomic.Int64
	once   sync.Once
}

func (b *countingResponseBody) Close() error {
	var err error
	b.once.Do(func() {
		b.closed.Add(1)
		err = b.ReadCloser.Close()
	})
	return err
}

func TestModernUpstreamConcurrentCallsUseUniqueIDsAndCloseBodies(t *testing.T) {
	const callCount = 32
	seenIDs := make(map[string]struct{}, callCount)
	var seenMu sync.Mutex
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := decodeModernWireRequest(t, r)
		var params sdk.CallToolParamsRaw
		if err := json.Unmarshal(request.params, &params); err != nil {
			t.Errorf("decode params: %v", err)
			return
		}
		var arguments struct {
			Value int `json:"value"`
		}
		if err := json.Unmarshal(params.Arguments, &arguments); err != nil {
			t.Errorf("decode arguments: %v", err)
			return
		}
		seenMu.Lock()
		seenIDs[string(request.id)] = struct{}{}
		seenMu.Unlock()
		requests.Add(1)
		writeModernResult(
			t,
			w,
			request.id,
			fmt.Sprintf(`{"structuredContent":{"value":%d,"requestID":%s}}`, arguments.Value, request.id),
		)
	}))
	t.Cleanup(srv.Close)

	tracker := &countingResponseRoundTripper{transport: sharedHTTPTransport}
	upstream := newTestModernUpstream(t, srv.URL, tracker)
	results := make([]json.RawMessage, callCount)
	errs := make([]error, callCount)
	var wg sync.WaitGroup
	for index := 0; index < callCount; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index], errs[index] = upstream.CallTool(
				context.Background(),
				"tool",
				json.RawMessage(fmt.Sprintf(`{"value":%d}`, index)),
			)
		}(index)
	}
	wg.Wait()

	for index := 0; index < callCount; index++ {
		if errs[index] != nil {
			t.Fatalf("call %d: %v", index, errs[index])
		}
		var result struct {
			StructuredContent struct {
				Value     int    `json:"value"`
				RequestID string `json:"requestID"`
			} `json:"structuredContent"`
		}
		if err := json.Unmarshal(results[index], &result); err != nil {
			t.Fatalf("decode result %d: %v", index, err)
		}
		if result.StructuredContent.Value != index || result.StructuredContent.RequestID == "" {
			t.Fatalf("result %d = %+v", index, result)
		}
	}
	if requests.Load() != callCount {
		t.Fatalf("requests = %d, want %d", requests.Load(), callCount)
	}
	seenMu.Lock()
	uniqueIDs := len(seenIDs)
	seenMu.Unlock()
	if uniqueIDs != callCount {
		t.Fatalf("unique IDs = %d, want %d", uniqueIDs, callCount)
	}
	if tracker.closed.Load() != callCount {
		t.Fatalf("closed bodies = %d, want %d", tracker.closed.Load(), callCount)
	}
}

func TestModernUpstreamValidatesHTTPConfigurationBeforeIO(t *testing.T) {
	var calls atomic.Int64
	transport := modernRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected request")
	})
	tests := []struct {
		name   string
		target appmcp.Target
	}{
		{
			name:   "invalid endpoint",
			target: appmcp.Target{URL: "https://user:password@example.com/mcp"},
		},
		{
			name: "reserved header",
			target: appmcp.Target{
				URL:     "https://example.com/mcp",
				Headers: map[string]string{"Mcp-Protocol-Version": "override"},
			},
		},
		{
			name: "session header",
			target: appmcp.Target{
				URL:     "https://example.com/mcp",
				Headers: map[string]string{"Mcp-Session-Id": "override"},
			},
		},
		{
			name: "parameter header",
			target: appmcp.Target{
				URL:     "https://example.com/mcp",
				Headers: map[string]string{"Mcp-Param-Token": "override"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newModernUpstreamWithTransport(
				tt.target,
				modernProtocolVersion,
				transport,
				testModernImplementationVersion,
			)
			if !errors.Is(err, appmcp.ErrUnreachable) {
				t.Fatalf("error = %v, want ErrUnreachable", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("network calls = %d", calls.Load())
	}
}
