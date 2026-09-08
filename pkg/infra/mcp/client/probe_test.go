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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/version"
)

const testProbeID = "trustgate-probe-1"

type probeReply struct {
	status      int
	contentType string
	body        string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingBody struct {
	reader io.Reader
	closed atomic.Bool
	read   atomic.Int64
}

func (b *trackingBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read.Add(int64(n))
	return n, err
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

type cancellationBody struct {
	ctx     context.Context
	started chan struct{}
	closed  atomic.Bool
}

func (b *cancellationBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.ctx.Done()
	return 0, errors.New("body read failed after cancellation")
}

func (b *cancellationBody) Close() error {
	b.closed.Store(true)
	return nil
}

func newProbeTarget(t *testing.T, replies func(int, map[string]any) probeReply) (appmcp.Target, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := int(calls.Add(1))
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var request map[string]any
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Errorf("decode request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		request["$headers"] = r.Header.Clone()
		reply := replies(call, request)
		if reply.contentType != "" {
			w.Header().Set("Content-Type", reply.contentType)
		}
		w.WriteHeader(reply.status)
		if _, err := io.WriteString(w, reply.body); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return appmcp.Target{URL: srv.URL}, &calls
}

func discoverResult(id any, versions ...string) string {
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"resultType":        "complete",
			"supportedVersions": versions,
			"capabilities":      map[string]any{},
		},
	})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func discoverError(id any, code int64, data any) string {
	rpcError := map[string]any{"code": code, "message": "probe error"}
	if data != nil {
		rpcError["data"] = data
	}
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   rpcError,
	})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func TestDecodeDiscoverProbeRetainsOnlyExplicitListChangedCapabilities(t *testing.T) {
	t.Parallel()
	raw := mustJSON(map[string]any{
		"jsonrpc": "2.0",
		"id":      testProbeID,
		"result": map[string]any{
			"resultType":        "complete",
			"supportedVersions": []string{modernProtocolVersion},
			"capabilities": map[string]any{
				"subscriptions": map[string]any{"listen": true},
				"tools":         map[string]any{"listChanged": true},
				"prompts":       map[string]any{"listChanged": false},
				"resources":     map[string]any{"subscribe": true},
			},
		},
	})
	_, result, err := decodeDiscoverProbeResponse([]byte(raw))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result == nil || !result.SubscriptionListen {
		t.Fatalf("result = %+v", result)
	}
	want := appmcp.ListChangedCapabilities{Tools: true}
	if !result.Capabilities.Equal(want) {
		t.Fatalf("capabilities = %+v, want %+v", result.Capabilities, want)
	}
}

func TestDecodeDiscoverProbeRejectsMalformedCapabilityTrio(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		capabilities map[string]any
	}{
		{
			name:         "kind is not object",
			capabilities: map[string]any{"tools": []string{}},
		},
		{
			name:         "list changed is not boolean",
			capabilities: map[string]any{"tools": map[string]any{"listChanged": "true"}},
		},
		{
			name:         "subscriptions is not object",
			capabilities: map[string]any{"subscriptions": true},
		},
		{
			name:         "listen is not boolean",
			capabilities: map[string]any{"subscriptions": map[string]any{"listen": "true"}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			raw := mustJSON(map[string]any{
				"jsonrpc": "2.0",
				"id":      testProbeID,
				"result": map[string]any{
					"resultType":        "complete",
					"supportedVersions": []string{modernProtocolVersion},
					"capabilities":      test.capabilities,
				},
			})
			if _, _, err := decodeDiscoverProbeResponse([]byte(raw)); err == nil {
				t.Fatal("expected malformed capability error")
			}
		})
	}
}

func newTestProbe(t *testing.T, _ appmcp.Target, versions ...string) *strictProbe {
	t.Helper()
	return newStrictProbe(sharedHTTPTransport, versions, "9.8.7")
}

func TestStrictProbeSendsDiscoverWire(t *testing.T) {
	t.Parallel()

	target, calls := newProbeTarget(t, func(_ int, request map[string]any) probeReply {
		if request["jsonrpc"] != "2.0" {
			t.Errorf("jsonrpc = %v", request["jsonrpc"])
		}
		if request["id"] != testProbeID {
			t.Errorf("id = %v", request["id"])
		}
		if request["method"] != "server/discover" {
			t.Errorf("method = %v", request["method"])
		}
		params, ok := request["params"].(map[string]any)
		if !ok {
			t.Errorf("params = %T", request["params"])
		}
		meta, ok := params["_meta"].(map[string]any)
		if !ok {
			t.Errorf("_meta = %T", params["_meta"])
		}
		if meta[metaProtocolVersion] != modernProtocolVersion {
			t.Errorf("protocol version = %v", meta[metaProtocolVersion])
		}
		info, ok := meta[metaClientInfo].(map[string]any)
		if !ok || info["name"] != "trustgate" || info["version"] != "9.8.7" {
			t.Errorf("client info = %#v", meta[metaClientInfo])
		}
		if capabilities, ok := meta[metaClientCapabilities].(map[string]any); !ok || len(capabilities) != 0 {
			t.Errorf("client capabilities = %#v", meta[metaClientCapabilities])
		}
		headers, ok := request["$headers"].(http.Header)
		if !ok {
			t.Errorf("headers = %T", request["$headers"])
		}
		if headers.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", headers.Get("Content-Type"))
		}
		if headers.Get("Accept") != "application/json, text/event-stream" {
			t.Errorf("Accept = %q", headers.Get("Accept"))
		}
		if headers.Get("Mcp-Protocol-Version") != modernProtocolVersion {
			t.Errorf("Mcp-Protocol-Version = %q", headers.Get("Mcp-Protocol-Version"))
		}
		if headers.Get("Mcp-Method") != "server/discover" {
			t.Errorf("Mcp-Method = %q", headers.Get("Mcp-Method"))
		}
		if headers.Get("User-Agent") != "trustgate/9.8.7" {
			t.Errorf("User-Agent = %q", headers.Get("User-Agent"))
		}
		if headers.Get("Authorization") != "Bearer target" {
			t.Errorf("Authorization = %q", headers.Get("Authorization"))
		}
		return probeReply{
			status:      http.StatusOK,
			contentType: "application/json",
			body:        discoverResult(testProbeID, modernProtocolVersion),
		}
	})
	target.Headers = map[string]string{"Authorization": "Bearer target"}

	outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if outcome.kind != probeModern || outcome.version != modernProtocolVersion {
		t.Fatalf("outcome = %+v", outcome)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestProtocolProbeUsesBuildVersion(t *testing.T) {
	t.Parallel()

	target, _ := newProbeTarget(t, func(_ int, request map[string]any) probeReply {
		headers := request["$headers"].(http.Header)
		if got, want := headers.Get("User-Agent"), "trustgate/"+version.Version; got != want {
			t.Errorf("User-Agent = %q, want %q", got, want)
		}
		params := request["params"].(map[string]any)
		meta := params["_meta"].(map[string]any)
		info := meta[metaClientInfo].(map[string]any)
		if got := info["version"]; got != version.Version {
			t.Errorf("client version = %v, want %q", got, version.Version)
		}
		return probeReply{
			status:      http.StatusOK,
			contentType: "application/json",
			body:        discoverResult(testProbeID, modernProtocolVersion),
		}
	})
	outcome, err := newProtocolProbe(sharedHTTPTransport).Probe(context.Background(), target)
	if err != nil || outcome.kind != probeModern {
		t.Fatalf("outcome = %+v, error = %v", outcome, err)
	}
}

func TestStrictProbeRejectsReservedTargetHeaderBeforeContact(t *testing.T) {
	t.Parallel()

	target, calls := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
		return probeReply{
			status:      http.StatusOK,
			contentType: "application/json",
			body:        discoverResult(testProbeID, modernProtocolVersion),
		}
	})
	target.Headers = map[string]string{"Content-Type": "text/plain"}
	outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if outcome.kind != probeUnknown {
		t.Fatalf("outcome = %+v", outcome)
	}
	if calls.Load() != 0 {
		t.Fatalf("calls = %d, want 0", calls.Load())
	}
}

func TestStrictProbeRejectsInvalidEndpointBeforeTransport(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected transport call")
	})
	tests := []struct {
		name string
		url  string
	}{
		{name: "userinfo", url: "https://user:password@example.com/mcp"},
		{name: "fragment", url: "https://example.com/mcp#secret"},
		{name: "empty explicit port", url: "https://example.com:/mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome, err := newStrictProbe(
				transport,
				[]string{modernProtocolVersion},
				"test",
			).Probe(context.Background(), appmcp.Target{URL: tt.url})
			if !errors.Is(err, appmcp.ErrUnreachable) {
				t.Fatalf("error = %v, want ErrUnreachable", err)
			}
			if outcome.kind != probeUnknown {
				t.Fatalf("outcome = %+v, want unknown", outcome)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("transport called %d times", calls.Load())
	}
}

func TestStrictProbeAcceptsJSONAndSSE(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        func(string) string
	}{
		{
			name:        "JSON",
			contentType: "application/json; charset=utf-8",
			body:        func(response string) string { return response },
		},
		{
			name:        "SSE LF",
			contentType: "text/event-stream",
			body: func(response string) string {
				return ": ping\n\nevent: message\ndata: " + response + "\n\n"
			},
		},
		{
			name:        "SSE CRLF",
			contentType: "text/event-stream",
			body: func(response string) string {
				return ": ping\r\n\r\nevent: message\r\ndata: " + response + "\r\n\r\n"
			},
		},
		{
			name:        "SSE CR",
			contentType: "text/event-stream",
			body: func(response string) string {
				return ": ping\r\revent: message\rdata: " + response + "\r\r"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{
					status:      http.StatusOK,
					contentType: tt.contentType,
					body:        tt.body(discoverResult(testProbeID, modernProtocolVersion)),
				}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if outcome.kind != probeModern || outcome.version != modernProtocolVersion {
				t.Fatalf("outcome = %+v", outcome)
			}
		})
	}
}

func TestStrictProbeRejectsInvalidSuccessfulResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "wrong ID", contentType: "application/json", body: discoverResult("other", modernProtocolVersion)},
		{name: "numeric ID", contentType: "application/json", body: discoverResult(1, modernProtocolVersion)},
		{name: "batch", contentType: "application/json", body: "[" + discoverResult(testProbeID, modernProtocolVersion) + "]"},
		{name: "unknown content type", contentType: "text/plain", body: discoverResult(testProbeID, modernProtocolVersion)},
		{name: "missing result type", contentType: "application/json", body: `{"jsonrpc":"2.0","id":"trustgate-probe-1","result":{"supportedVersions":["2026-07-28"],"capabilities":{}}}`},
		{name: "missing capabilities", contentType: "application/json", body: `{"jsonrpc":"2.0","id":"trustgate-probe-1","result":{"resultType":"complete","supportedVersions":["2026-07-28"]}}`},
		{name: "multiple SSE messages", contentType: "text/event-stream", body: "data: " + discoverResult(testProbeID, modernProtocolVersion) + "\n\ndata: " + discoverResult(testProbeID, modernProtocolVersion) + "\n\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{status: http.StatusOK, contentType: tt.contentType, body: tt.body}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if err == nil {
				t.Fatalf("outcome = %+v, want error", outcome)
			}
			if outcome.kind != probeUnknown {
				t.Fatalf("outcome kind = %v, want unknown", outcome.kind)
			}
		})
	}
}

func TestStrictProbeClassifiesModernErrorCodes(t *testing.T) {
	t.Parallel()

	for _, code := range []int64{codeHeaderMismatch, codeRequiredCapability} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			t.Parallel()
			target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{
					status:      http.StatusBadRequest,
					contentType: "application/json",
					body:        discoverError(testProbeID, code, nil),
				}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if outcome.kind != probeModern || outcome.version != modernProtocolVersion {
				t.Fatalf("outcome = %+v", outcome)
			}
		})
	}
}

func TestStrictProbeRejectsHTTPBadRequestResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "valid result", body: discoverResult(testProbeID, modernProtocolVersion)},
		{name: "null result", body: `{"jsonrpc":"2.0","id":"trustgate-probe-1","result":null}`},
		{name: "invalid result", body: `{"jsonrpc":"2.0","id":"trustgate-probe-1","result":{"resultType":"invalid"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{
					status:      http.StatusBadRequest,
					contentType: "application/json",
					body:        tt.body,
				}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if err == nil {
				t.Fatal("expected HTTP 400 result to fail")
			}
			if outcome.kind != probeUnknown {
				t.Fatalf("outcome = %+v, want unknown", outcome)
			}
			var probeErr *probeClassificationError
			if !errors.As(err, &probeErr) {
				t.Fatalf("error = %T, want probeClassificationError", err)
			}
			if probeErr.code != probeErrorUnexpectedBadRequestResult {
				t.Fatalf("probe error code = %q", probeErr.code)
			}
		})
	}
}

func TestStrictProbeRejectsHTTPBadRequestMultiEventSSEResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result string
	}{
		{name: "valid result", result: discoverResult(testProbeID, modernProtocolVersion)},
		{name: "null result", result: `{"jsonrpc":"2.0","id":"trustgate-probe-1","result":null}`},
		{name: "invalid result", result: `{"jsonrpc":"2.0","id":"trustgate-probe-1","result":{"resultType":"invalid"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{
					status:      http.StatusBadRequest,
					contentType: "text/event-stream",
					body: "data: " + discoverError(testProbeID, -32601, nil) +
						"\n\ndata: " + tt.result + "\n\n",
				}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if err == nil {
				t.Fatal("expected HTTP 400 multi-event SSE result to fail")
			}
			if outcome.kind == probeLegacyCandidate {
				t.Fatalf("outcome = %+v, must not be legacy candidate", outcome)
			}
			var probeErr *probeClassificationError
			if !errors.As(err, &probeErr) || probeErr.code != probeErrorUnexpectedBadRequestResult {
				t.Fatalf("error = %v, want unexpected bad request result", err)
			}
		})
	}
}

func TestStrictProbeRejectsHTTPBadRequestCRSSEResult(t *testing.T) {
	t.Parallel()

	results := []struct {
		name string
		body string
	}{
		{name: "valid result", body: discoverResult(testProbeID, modernProtocolVersion)},
		{name: "null result", body: `{"jsonrpc":"2.0","id":"trustgate-probe-1","result":null}`},
		{name: "invalid result", body: `{"jsonrpc":"2.0","id":"trustgate-probe-1","result":{"resultType":"invalid"}}`},
	}
	for _, result := range results {
		for _, eventCount := range []string{"single event", "multiple events"} {
			t.Run(eventCount+"/"+result.name, func(t *testing.T) {
				t.Parallel()
				body := "data: " + result.body + "\r\r"
				if eventCount == "multiple events" {
					body = "data: " + discoverError(testProbeID, -32601, nil) +
						"\r\rdata: " + result.body + "\r\r"
				}
				target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
					return probeReply{
						status:      http.StatusBadRequest,
						contentType: "text/event-stream",
						body:        body,
					}
				})
				outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
				if err == nil {
					t.Fatal("expected HTTP 400 CR SSE result to fail")
				}
				if outcome.kind == probeLegacyCandidate {
					t.Fatalf("outcome = %+v, must not be legacy candidate", outcome)
				}
				var probeErr *probeClassificationError
				if !errors.As(err, &probeErr) || probeErr.code != probeErrorUnexpectedBadRequestResult {
					t.Fatalf("error = %v, want unexpected bad request result", err)
				}
			})
		}
	}
}

func TestStrictProbeRejectsModernErrorOnNegotiationRetry(t *testing.T) {
	t.Parallel()

	for _, code := range []int64{
		codeHeaderMismatch,
		codeRequiredCapability,
		codeUnsupportedProtocolVersion,
	} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			t.Parallel()
			target, calls := newProbeTarget(t, func(call int, _ map[string]any) probeReply {
				if call == 1 {
					return probeReply{
						status:      http.StatusBadRequest,
						contentType: "application/json",
						body: discoverError(testProbeID, codeUnsupportedProtocolVersion, map[string]any{
							"supported": []string{modernProtocolVersion},
						}),
					}
				}
				return probeReply{
					status:      http.StatusBadRequest,
					contentType: "application/json",
					body: discoverError(testProbeID, code, map[string]any{
						"supported": []string{modernProtocolVersion},
					}),
				}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if !errors.Is(err, appmcp.ErrProtocolIncompatible) {
				t.Fatalf("error = %v, want ErrProtocolIncompatible", err)
			}
			if outcome.kind != probeModernIncompatible || calls.Load() != 2 {
				t.Fatalf("outcome = %+v, calls = %d", outcome, calls.Load())
			}
		})
	}
}

func TestStrictProbeSanitizesRPCClassificationError(t *testing.T) {
	t.Parallel()

	const secret = "upstream-secret-value"
	target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
		raw, marshalErr := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      testProbeID,
			"error": map[string]any{
				"code":    -32603,
				"message": secret,
				"data":    map[string]any{"token": secret},
			},
		})
		if marshalErr != nil {
			t.Errorf("marshal error response: %v", marshalErr)
		}
		return probeReply{
			status:      http.StatusOK,
			contentType: "application/json",
			body:        string(raw),
		}
	})
	outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
	if err == nil {
		t.Fatal("expected RPC classification error")
	}
	if outcome.kind != probeUnknown {
		t.Fatalf("outcome = %+v, want unknown", outcome)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("classification error leaked upstream data: %v", err)
	}
	var probeErr *probeClassificationError
	if !errors.As(err, &probeErr) {
		t.Fatalf("error = %T, want probeClassificationError", err)
	}
	if probeErr.code != probeErrorRPC || probeErr.rpcCode != -32603 {
		t.Fatalf("probe error = %+v", probeErr)
	}
}

func TestStrictProbeNegotiatesUnsupportedVersionOnce(t *testing.T) {
	t.Parallel()

	versions := []string{"2026-09-01", modernProtocolVersion}
	var mu sync.Mutex
	var requested []string
	target, calls := newProbeTarget(t, func(call int, request map[string]any) probeReply {
		params := request["params"].(map[string]any)
		meta := params["_meta"].(map[string]any)
		mu.Lock()
		requested = append(requested, meta[metaProtocolVersion].(string))
		mu.Unlock()
		if call == 1 {
			return probeReply{
				status:      http.StatusBadRequest,
				contentType: "application/json",
				body: discoverError(testProbeID, codeUnsupportedProtocolVersion, map[string]any{
					"supported": []string{modernProtocolVersion, "2025-11-25"},
					"requested": versions[0],
				}),
			}
		}
		return probeReply{
			status:      http.StatusOK,
			contentType: "application/json",
			body:        discoverResult(testProbeID, modernProtocolVersion),
		}
	})

	outcome, err := newTestProbe(t, target, versions...).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if outcome.kind != probeModern || outcome.version != modernProtocolVersion {
		t.Fatalf("outcome = %+v", outcome)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requested) != 2 || requested[0] != versions[0] || requested[1] != modernProtocolVersion {
		t.Fatalf("requested versions = %v", requested)
	}
}

func TestStrictProbeDowngradesToLegacyWhenOnlyLegacyVersionsAdvertised(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		reply probeReply
	}{
		{
			name: "discover result advertises legacy versions only",
			reply: probeReply{
				status:      http.StatusOK,
				contentType: "application/json",
				body:        discoverResult(testProbeID, "2025-11-25", "2025-06-18"),
			},
		},
		{
			name: "version rejection advertises legacy versions only",
			reply: probeReply{
				status:      http.StatusBadRequest,
				contentType: "application/json",
				body: discoverError(testProbeID, codeUnsupportedProtocolVersion, map[string]any{
					"supported": []string{"2025-06-18"},
					"requested": modernProtocolVersion,
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target, calls := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return tt.reply
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if outcome.kind != probeLegacyCandidate {
				t.Fatalf("outcome = %+v, want probeLegacyCandidate", outcome)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestStrictProbeNeverFallsBackAfterModernIncompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data map[string]any
	}{
		{
			name: "no mutually supported version",
			data: map[string]any{"supported": []string{"2027-05-01"}},
		},
		{
			name: "missing supported versions",
			data: map[string]any{"requested": modernProtocolVersion},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target, calls := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{
					status:      http.StatusBadRequest,
					contentType: "application/json",
					body:        discoverError(testProbeID, codeUnsupportedProtocolVersion, tt.data),
				}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if !errors.Is(err, appmcp.ErrProtocolIncompatible) {
				t.Fatalf("error = %v, want ErrProtocolIncompatible", err)
			}
			if outcome.kind != probeModernIncompatible {
				t.Fatalf("outcome = %+v", outcome)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d, want 1", calls.Load())
			}
		})
	}

	t.Run("repeated unsupported response", func(t *testing.T) {
		t.Parallel()
		target, calls := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
			return probeReply{
				status:      http.StatusBadRequest,
				contentType: "application/json",
				body: discoverError(testProbeID, codeUnsupportedProtocolVersion, map[string]any{
					"supported": []string{modernProtocolVersion},
				}),
			}
		})
		outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
		if !errors.Is(err, appmcp.ErrProtocolIncompatible) {
			t.Fatalf("error = %v, want ErrProtocolIncompatible", err)
		}
		if outcome.kind != probeModernIncompatible || calls.Load() != 2 {
			t.Fatalf("outcome = %+v, calls = %d", outcome, calls.Load())
		}
	})

	t.Run("malformed negotiation retry", func(t *testing.T) {
		t.Parallel()
		target, calls := newProbeTarget(t, func(call int, _ map[string]any) probeReply {
			if call == 1 {
				return probeReply{
					status:      http.StatusBadRequest,
					contentType: "application/json",
					body: discoverError(testProbeID, codeUnsupportedProtocolVersion, map[string]any{
						"supported": []string{modernProtocolVersion},
					}),
				}
			}
			return probeReply{status: http.StatusBadRequest, contentType: "application/json", body: "{"}
		})
		outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
		if !errors.Is(err, appmcp.ErrUnreachable) {
			t.Fatalf("error = %v, want ErrUnreachable", err)
		}
		if outcome.kind == probeLegacyCandidate || calls.Load() != 2 {
			t.Fatalf("outcome = %+v, calls = %d", outcome, calls.Load())
		}
	})

	t.Run("contradictory successful retry", func(t *testing.T) {
		t.Parallel()
		versions := []string{"2026-09-01", modernProtocolVersion}
		target, calls := newProbeTarget(t, func(call int, _ map[string]any) probeReply {
			if call == 1 {
				return probeReply{
					status:      http.StatusBadRequest,
					contentType: "application/json",
					body: discoverError(testProbeID, codeUnsupportedProtocolVersion, map[string]any{
						"supported": []string{modernProtocolVersion},
					}),
				}
			}
			return probeReply{
				status:      http.StatusOK,
				contentType: "application/json",
				body:        discoverResult(testProbeID, versions[0]),
			}
		})
		outcome, err := newTestProbe(t, target, versions...).Probe(context.Background(), target)
		if !errors.Is(err, appmcp.ErrProtocolIncompatible) {
			t.Fatalf("error = %v, want ErrProtocolIncompatible", err)
		}
		if outcome.kind != probeModernIncompatible || calls.Load() != 2 {
			t.Fatalf("outcome = %+v, calls = %d", outcome, calls.Load())
		}
	})
}

func TestStrictProbeClassifiesOnlyAmbiguousBadRequestAsLegacyCandidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "empty", contentType: "text/plain", body: ""},
		{name: "malformed", contentType: "application/json", body: "{"},
		{name: "unrecognized RPC code", contentType: "application/json", body: discoverError(testProbeID, -32601, nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{
					status:      http.StatusBadRequest,
					contentType: tt.contentType,
					body:        tt.body,
				}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if outcome.kind != probeLegacyCandidate {
				t.Fatalf("outcome = %+v", outcome)
			}
		})
	}
}

func TestStrictProbeHTTPStatusMatrixIsInconclusive(t *testing.T) {
	t.Parallel()

	statuses := []int{
		http.StatusMultipleChoices,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{
					status:      status,
					contentType: "text/plain",
					body:        "sensitive-response-body",
				}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if !errors.Is(err, appmcp.ErrUnreachable) {
				t.Fatalf("error = %v, want ErrUnreachable", err)
			}
			if strings.Contains(err.Error(), "sensitive-response-body") {
				t.Fatalf("error leaked response body: %v", err)
			}
			if outcome.kind != probeUnknown {
				t.Fatalf("outcome = %+v", outcome)
			}
		})
	}
}

func TestStrictProbeBoundsResponseBody(t *testing.T) {
	t.Parallel()

	valid := discoverResult(testProbeID, modernProtocolVersion)
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "exactly 64 KiB", size: maxProbeBodyBytes},
		{name: "over 64 KiB", size: maxProbeBodyBytes + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := valid + strings.Repeat(" ", tt.size-len(valid))
			target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
				return probeReply{status: http.StatusOK, contentType: "application/json", body: body}
			})
			outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
			if tt.wantErr {
				if !errors.Is(err, errProbeBodyTooLarge) {
					t.Fatalf("error = %v, want errProbeBodyTooLarge", err)
				}
				if outcome.kind != probeUnknown {
					t.Fatalf("outcome = %+v", outcome)
				}
				return
			}
			if err != nil || outcome.kind != probeModern {
				t.Fatalf("outcome = %+v, error = %v", outcome, err)
			}
		})
	}
}

func TestStrictProbeClosesResponseBody(t *testing.T) {
	t.Parallel()

	readFailure := errors.New("read failure")
	tests := []struct {
		name    string
		body    *trackingBody
		wantErr error
	}{
		{
			name: "success",
			body: &trackingBody{reader: strings.NewReader(discoverResult(testProbeID, modernProtocolVersion))},
		},
		{
			name:    "overflow",
			body:    &trackingBody{reader: repeatingReader{}},
			wantErr: errProbeBodyTooLarge,
		},
		{
			name:    "read error",
			body:    &trackingBody{reader: failingReader{err: readFailure}},
			wantErr: readFailure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       tt.body,
					Request:    req,
				}, nil
			})
			target := appmcp.Target{URL: "https://example.com/mcp"}
			outcome, err := newStrictProbe(transport, []string{modernProtocolVersion}, "test").Probe(
				context.Background(),
				target,
			)
			if tt.wantErr == nil {
				if err != nil || outcome.kind != probeModern {
					t.Fatalf("outcome = %+v, error = %v", outcome, err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if !tt.body.closed.Load() {
				t.Fatal("response body was not closed")
			}
			if tt.name == "overflow" && tt.body.read.Load() != maxProbeBodyBytes+1 {
				t.Fatalf("overflow bytes read = %d, want %d", tt.body.read.Load(), maxProbeBodyBytes+1)
			}
		})
	}
}

func TestStrictProbePreservesCancellationAndNetworkErrors(t *testing.T) {
	t.Parallel()

	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()
		started := make(chan struct{})
		target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
			close(started)
			time.Sleep(250 * time.Millisecond)
			return probeReply{status: http.StatusOK, contentType: "application/json", body: discoverResult(testProbeID, modernProtocolVersion)}
		})
		ctx, cancel := context.WithCancel(context.Background())
		probe := newTestProbe(t, target, modernProtocolVersion)
		done := make(chan error, 1)
		go func() {
			_, err := probe.Probe(ctx, target)
			done <- err
		}()
		<-started
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
		case <-time.After(time.Second):
			t.Fatal("probe did not return after cancellation")
		}
	})

	t.Run("network", func(t *testing.T) {
		t.Parallel()
		target := appmcp.Target{URL: "http://127.0.0.1:1/mcp"}
		outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(context.Background(), target)
		if !errors.Is(err, appmcp.ErrUnreachable) {
			t.Fatalf("error = %v, want ErrUnreachable", err)
		}
		if outcome.kind != probeUnknown {
			t.Fatalf("outcome = %+v", outcome)
		}
	})

	t.Run("network error sanitizes URL query", func(t *testing.T) {
		t.Parallel()
		const secret = "probe-query-secret-sentinel"
		networkErr := errors.New("network unavailable")
		transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: http.MethodPost, URL: req.URL.String(), Err: networkErr}
		})
		target := appmcp.Target{URL: "https://example.com/mcp?token=" + secret}
		outcome, err := newStrictProbe(
			transport,
			[]string{modernProtocolVersion},
			"test",
		).Probe(context.Background(), target)
		if !errors.Is(err, appmcp.ErrUnreachable) || !errors.Is(err, networkErr) {
			t.Fatalf("error = %v, want ErrUnreachable and network cause", err)
		}
		var urlErr *url.Error
		if !errors.As(err, &urlErr) {
			t.Fatalf("error = %T, want wrapped url.Error", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error exposed URL query: %v", err)
		}
		if outcome.kind != probeUnknown {
			t.Fatalf("outcome = %+v", outcome)
		}
	})

	t.Run("cancelled during body read", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		bodyCh := make(chan *cancellationBody, 1)
		transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := &cancellationBody{ctx: req.Context(), started: make(chan struct{})}
			bodyCh <- body
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       body,
				Request:    req,
			}, nil
		})
		target := appmcp.Target{URL: "https://example.com/mcp"}
		done := make(chan error, 1)
		go func() {
			_, err := newStrictProbe(
				transport,
				[]string{modernProtocolVersion},
				"test",
			).Probe(ctx, target)
			done <- err
		}()
		body := <-bodyCh
		<-body.started
		cancel()
		select {
		case err := <-done:
			if err != context.Canceled {
				t.Fatalf("error = %v, want direct context.Canceled", err)
			}
		case <-time.After(time.Second):
			t.Fatal("probe did not return after body-read cancellation")
		}
		if !body.closed.Load() {
			t.Fatal("response body was not closed")
		}
	})

	t.Run("deadline", func(t *testing.T) {
		t.Parallel()
		target, _ := newProbeTarget(t, func(_ int, _ map[string]any) probeReply {
			time.Sleep(250 * time.Millisecond)
			return probeReply{status: http.StatusOK, contentType: "application/json", body: discoverResult(testProbeID, modernProtocolVersion)}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		outcome, err := newTestProbe(t, target, modernProtocolVersion).Probe(ctx, target)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error = %v, want context.DeadlineExceeded", err)
		}
		if outcome.kind != probeUnknown {
			t.Fatalf("outcome = %+v", outcome)
		}
	})
}

const appsPositive = `{"extensions":{"io.modelcontextprotocol/ui":{"mimeTypes":["text/html;profile=mcp-app"]}}}`

func appsResponse(capabilities string) *http.Response {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"%s","result":{"resultType":"complete","supportedVersions":["%s"],"capabilities":%s}}`,
		probeRequestID, modernProtocolVersion, capabilities)
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(body))}
}
func testAppsResolver(transport http.RoundTripper) *AppCapabilityResolver {
	resolver := NewAppCapabilityResolver(cache.NewTTLMap(cache.MCPAppsCacheTTL))
	resolver.transport = transport
	return resolver
}

type appsCredentialPassthrough struct{}

func (appsCredentialPassthrough) Apply(context.Context, *appconsumer.RoutableConsumer, *registrydomain.Registry, *appmcp.Target) error {
	return nil
}

func TestAppsMediatorCancelsRealResolverFlights(t *testing.T) {
	started := make(chan struct{}, 2)
	var active atomic.Int32
	resolver := testAppsResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "positive.example" {
			<-started
			<-started
			return appsResponse(appsPositive), nil
		}
		active.Add(1)
		started <- struct{}{}
		defer active.Add(-1)
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{}}
	for _, host := range []string{"slow-a.example", "slow-b.example", "positive.example"} {
		rc.Registries = append(rc.Registries, &registrydomain.Registry{
			ID: ids.New[ids.RegistryKind](), Type: registrydomain.TypeMCP, Enabled: true,
			MCPTarget: &registrydomain.MCPTarget{URL: "https://" + host + "/mcp", ProtocolMode: registrydomain.MCPProtocolModeModern},
		})
	}
	if !appmcp.NewAppsMediator(true, true, appsCredentialPassthrough{}, resolver).
		Advertise(context.Background(), true, rc, appmcp.MCPAppsClientCapability{MIMETypes: []string{appmcp.MCPAppsHTMLMIMEType}}) {
		t.Fatal("positive real resolver did not advertise")
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if active.Load() != 0 || len(resolver.flights) != 0 {
		t.Fatalf("active=%d flights=%d", active.Load(), len(resolver.flights))
	}
}

func TestParseAppsCapability(t *testing.T) {
	tests := map[string]error{
		`{}`: ErrAppCapabilityUnsupported,
		`{"io.modelcontextprotocol/ui":{"mimeTypes":["text/plain"]}}`: ErrAppCapabilityUnsupported,
		`[]`:                                ErrAppCapabilityProtocol,
		`{"io.modelcontextprotocol/ui":[]}`: ErrAppCapabilityProtocol,
		`{"io.modelcontextprotocol/ui":{}}`: ErrAppCapabilityProtocol,
		`{"io.modelcontextprotocol/ui":{"mimeTypes":"text/plain"}}`: ErrAppCapabilityProtocol,
	}
	for raw, want := range tests {
		_, err := parseAppsCapability(&discoverProbeResult{ExtensionsRaw: json.RawMessage(raw)})
		if !errors.Is(err, want) {
			t.Fatalf("%s: error = %v, want %v", raw, err, want)
		}
	}
}
func TestAppCapabilityResolverSafetyAndCache(t *testing.T) {
	now := time.Unix(100, 0)
	resolver := testAppsResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var request map[string]any
		_ = json.NewDecoder(req.Body).Decode(&request)
		meta := request["params"].(map[string]any)["_meta"].(map[string]any)
		if req.Header.Get("Authorization") != "Bearer one" ||
			mustJSON(meta[metaClientCapabilities]) != appsPositive {
			t.Fatal("credentialed Apps declaration missing")
		}
		return appsResponse(appsPositive), nil
	}))
	resolver.now = func() time.Time { return now }
	target := appmcp.Target{URL: "https://upstream.example/mcp?tenant=a", RegistryTargetID: "registry",
		PinKey: "identity", Headers: map[string]string{"authorization": "Bearer one", "X-Tenant": "a"}}
	if _, err := resolver.Resolve(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	keyFor := func(headers map[string]string) string {
		target.Headers = headers
		key, _ := appCapabilityCacheKey(target)
		return key
	}
	sameKey := keyFor(map[string]string{"X-Tenant": "a", "Authorization": "Bearer one"})
	if keyFor(map[string]string{"authorization": "Bearer one", "X-Tenant": "a"}) != sameKey ||
		keyFor(map[string]string{"Authorization": "Bearer two", "X-Tenant": "a"}) == sameKey {
		t.Fatal("cache key is not canonical and credential-bound")
	}
	if resolver.result(appmcp.MCPAppsClientCapability{}, nil).expiresAt.Sub(now) != cache.MCPAppsCacheTTL ||
		resolver.result(appmcp.MCPAppsClientCapability{}, ErrAppCapabilityUnsupported).expiresAt.Sub(now) != appCapabilityNegativeTTL {
		t.Fatal("capability TTL mismatch")
	}
	for _, headers := range []map[string]string{{"Host": "bad"}, {"Bad Header": "bad"}, {"X-Test": "bad\nvalue"}} {
		target.Headers = headers
		if _, err := resolver.Resolve(context.Background(), target); !errors.Is(err, appmcp.ErrUnreachable) {
			t.Fatalf("unsafe header error = %v", err)
		}
	}
	target.ProtocolMode = registrydomain.MCPProtocolModeLegacy
	if _, err := resolver.Resolve(context.Background(), target); !errors.Is(err, ErrAppCapabilityUnsupported) {
		t.Fatalf("legacy error = %v", err)
	}
}

func TestAppCapabilityResolverWaiterCancellation(t *testing.T) {
	cancelled, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}, 3)
	var calls atomic.Int64
	resolver := testAppsResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			<-req.Context().Done()
			close(cancelled)
			<-release
			return nil, req.Context().Err()
		}
		return appsResponse(appsPositive), nil
	}))
	resolver.joined = func() { joined <- struct{}{} }
	target := appmcp.Target{URL: "https://upstream.example/mcp", RegistryTargetID: "registry"}
	result1, result2, retry := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { _, err := resolver.Resolve(ctx1, target); result1 <- err }()
	go func() { _, err := resolver.Resolve(ctx2, target); result2 <- err }()
	<-joined
	<-joined
	cancel1()
	if err := <-result1; !errors.Is(err, context.Canceled) {
		t.Fatalf("first error = %v", err)
	}
	cancel2()
	<-cancelled
	go func() { _, err := resolver.Resolve(context.Background(), target); retry <- err }()
	<-joined
	if calls.Load() != 1 {
		t.Fatal("retry overlapped cancelled probe")
	}
	close(release)
	if err := <-result2; !errors.Is(err, context.Canceled) {
		t.Fatalf("second error = %v", err)
	}
	if err := <-retry; err != nil || calls.Load() != 2 || len(resolver.flights) != 0 {
		t.Fatalf("retry error=%v calls=%d flights=%d", err, calls.Load(), len(resolver.flights))
	}
}
