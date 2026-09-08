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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type subscriptionProbeResult struct {
	outcome probeOutcome
	err     error
}

type byteReadCloser struct {
	data   []byte
	offset int
}

func (r *byteReadCloser) Read(buffer []byte) (int, error) {
	if r.offset == len(r.data) {
		return 0, io.EOF
	}
	buffer[0] = r.data[r.offset]
	r.offset++
	return 1, nil
}

func (*byteReadCloser) Close() error {
	return nil
}

func (p subscriptionProbeResult) Probe(context.Context, appmcp.Target) (probeOutcome, error) {
	return p.outcome, p.err
}

func TestModernSubscriptionPrepareRequiresExactModernCapabilityContract(t *testing.T) {
	t.Parallel()
	target := appmcp.Target{
		URL:              "https://upstream.example/mcp",
		RegistryTargetID: "registry",
		ProtocolMode:     registrydomain.MCPProtocolModeModern,
		Headers:          map[string]string{"Authorization": "Bearer secret"},
	}
	capabilities := appmcp.ListChangedCapabilities{Tools: true, Resources: true}
	tests := []struct {
		name    string
		target  appmcp.Target
		outcome probeOutcome
		err     error
		wantErr error
	}{
		{
			name:   "supported",
			target: target,
			outcome: probeOutcome{
				kind:               probeModern,
				version:            modernProtocolVersion,
				capabilities:       capabilities,
				subscriptionListen: true,
			},
		},
		{
			name: "legacy source",
			target: func() appmcp.Target {
				value := target
				value.ProtocolMode = registrydomain.MCPProtocolModeLegacy
				return value
			}(),
			outcome: probeOutcome{
				kind:               probeModern,
				version:            modernProtocolVersion,
				capabilities:       capabilities,
				subscriptionListen: true,
			},
			wantErr: appmcp.ErrSubscriptionUnsupported,
		},
		{
			name:   "unsupported version",
			target: target,
			outcome: probeOutcome{
				kind:               probeModern,
				version:            "2025-11-25",
				capabilities:       capabilities,
				subscriptionListen: true,
			},
			wantErr: appmcp.ErrSubscriptionUnsupported,
		},
		{
			name:   "listen absent",
			target: target,
			outcome: probeOutcome{
				kind:         probeModern,
				version:      modernProtocolVersion,
				capabilities: capabilities,
			},
			wantErr: appmcp.ErrSubscriptionUnsupported,
		},
		{
			name:   "empty trio",
			target: target,
			outcome: probeOutcome{
				kind:               probeModern,
				version:            modernProtocolVersion,
				subscriptionListen: true,
			},
			wantErr: appmcp.ErrSubscriptionUnsupported,
		},
		{
			name:    "discovery error",
			target:  target,
			err:     appmcp.ErrUnreachable,
			wantErr: appmcp.ErrUnreachable,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			connector := &modernSubscriptionConnector{
				probe:         subscriptionProbeResult{outcome: test.outcome, err: test.err},
				transport:     sharedHTTPTransport,
				maxEventBytes: 1024,
				idleTimeout:   time.Second,
			}
			prepared, err := connector.Prepare(context.Background(), test.target)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil {
				if !prepared.Capabilities.Equal(capabilities) {
					t.Fatalf("capabilities = %+v", prepared.Capabilities)
				}
				formatted := fmt.Sprint(prepared)
				if strings.Contains(formatted, "secret") || strings.Contains(formatted, "upstream.example") {
					t.Fatalf("prepared source exposed material: %q", formatted)
				}
			}
		})
	}
}

func TestSubscriptionSourceKeyPartitionsEveryIdentityComponent(t *testing.T) {
	t.Parallel()
	base := appmcp.Target{
		URL:              "https://UPSTREAM.example:443/mcp",
		RegistryTargetID: "registry-a",
		PinKey:           "pin-a",
		Headers:          map[string]string{"Authorization": "Bearer one"},
	}
	capabilities := appmcp.ListChangedCapabilities{Tools: true}
	baseKey, err := subscriptionSourceKey(base, capabilities)
	if err != nil {
		t.Fatalf("base key: %v", err)
	}
	equivalent := base
	equivalent.URL = "https://upstream.example/mcp"
	equivalentKey, err := subscriptionSourceKey(equivalent, capabilities)
	if err != nil {
		t.Fatalf("equivalent key: %v", err)
	}
	if equivalentKey != baseKey {
		t.Fatal("canonical equivalents produced different keys")
	}
	mutations := []struct {
		name         string
		target       appmcp.Target
		capabilities appmcp.ListChangedCapabilities
	}{
		{name: "target", target: func() appmcp.Target { v := base; v.URL = "https://upstream.example/other"; return v }(), capabilities: capabilities},
		{name: "origin", target: func() appmcp.Target { v := base; v.URL = "https://other.example/mcp"; return v }(), capabilities: capabilities},
		{name: "registry target", target: func() appmcp.Target { v := base; v.RegistryTargetID = "registry-b"; return v }(), capabilities: capabilities},
		{name: "pin", target: func() appmcp.Target { v := base; v.PinKey = "pin-b"; return v }(), capabilities: capabilities},
		{name: "credential", target: func() appmcp.Target {
			v := base
			v.Headers = map[string]string{"Authorization": "Bearer two"}
			return v
		}(), capabilities: capabilities},
		{name: "capabilities", target: base, capabilities: appmcp.ListChangedCapabilities{Tools: true, Prompts: true}},
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			t.Parallel()
			got, err := subscriptionSourceKey(mutation.target, mutation.capabilities)
			if err != nil {
				t.Fatalf("source key: %v", err)
			}
			if got == baseKey {
				t.Fatal("identity mutation did not partition the source key")
			}
		})
	}
}

func TestModernSubscriptionOpenAcknowledgesThenStreamsAllowListedEvents(t *testing.T) {
	t.Parallel()
	capabilities := appmcp.ListChangedCapabilities{Tools: true, Resources: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Mcp-Protocol-Version") != modernProtocolVersion {
			t.Errorf("protocol = %q", r.Header.Get("Mcp-Protocol-Version"))
		}
		if r.Header.Get("Authorization") != "Bearer resolved" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Mcp-Session-Id") != "" || r.Header.Get("Last-Event-ID") != "" {
			t.Errorf("session headers = %v", r.Header)
		}
		var request struct {
			Method string `json:"method"`
			Params struct {
				Notifications map[string]bool `json:"notifications"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request.Method != appmcp.MethodSubscriptionsListen ||
			!request.Params.Notifications[string(appmcp.NotificationToolsListChanged)] ||
			!request.Params.Notifications[string(appmcp.NotificationResourcesListChanged)] ||
			request.Params.Notifications[string(appmcp.NotificationPromptsListChanged)] {
			t.Errorf("request = %+v", request)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		writeSSEData(t, w, subscriptionAck(capabilities))
		writeSSEData(t, w, `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`)
	}))
	defer server.Close()
	target := appmcp.Target{
		URL:              server.URL + "/mcp",
		RegistryTargetID: "registry",
		PinKey:           "pin",
		Headers:          map[string]string{"Authorization": "Bearer resolved"},
	}
	connector, prepared := testSubscriptionConnector(t, server, target, capabilities, time.Second, 1024)
	stream, err := connector.Open(context.Background(), target, prepared)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer stream.Close()
	if !stream.Acknowledged().Equal(capabilities) {
		t.Fatalf("acknowledged = %+v", stream.Acknowledged())
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if event.Kind != appmcp.NotificationToolsListChanged {
		t.Fatalf("event = %+v", event)
	}
}

func TestModernSubscriptionOpenRejectsAcknowledgementDrift(t *testing.T) {
	t.Parallel()
	preparedCapabilities := appmcp.ListChangedCapabilities{Tools: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSEData(t, w, subscriptionAck(appmcp.ListChangedCapabilities{Tools: true, Prompts: true}))
	}))
	defer server.Close()
	target := appmcp.Target{URL: server.URL, RegistryTargetID: "registry", Headers: map[string]string{}}
	connector, prepared := testSubscriptionConnector(t, server, target, preparedCapabilities, time.Second, 1024)
	_, err := connector.Open(context.Background(), target, prepared)
	if !errors.Is(err, appmcp.ErrSubscriptionSourceChanged) {
		t.Fatalf("error = %v", err)
	}
}

func TestModernSubscriptionStreamRejectsDisallowedAndOversizeEvents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		event         string
		maxEventBytes int
	}{
		{
			name:          "unknown notification",
			event:         `{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{}}`,
			maxEventBytes: 1024,
		},
		{
			name:          "task notification",
			event:         `{"jsonrpc":"2.0","method":"notifications/tasks/status","params":{}}`,
			maxEventBytes: 1024,
		},
		{
			name:          "unknown method",
			event:         `{"jsonrpc":"2.0","method":"notifications/vendor/changed","params":{}}`,
			maxEventBytes: 1024,
		},
		{
			name:          "malformed JSON-RPC",
			event:         `{"jsonrpc":"2.0","method":`,
			maxEventBytes: 1024,
		},
		{
			name:          "unexpected result",
			event:         `{"jsonrpc":"2.0","id":"other","result":{}}`,
			maxEventBytes: 1024,
		},
		{
			name:          "oversize data",
			event:         strings.Repeat("x", 513),
			maxEventBytes: 512,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			capabilities := appmcp.ListChangedCapabilities{Tools: true}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				writeSSEData(t, w, subscriptionAck(capabilities))
				writeSSEData(t, w, test.event)
			}))
			defer server.Close()
			target := appmcp.Target{URL: server.URL, RegistryTargetID: "registry", Headers: map[string]string{}}
			connector, prepared := testSubscriptionConnector(
				t,
				server,
				target,
				capabilities,
				time.Second,
				test.maxEventBytes,
			)
			stream, err := connector.Open(context.Background(), target, prepared)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer stream.Close()
			_, err = stream.Next(context.Background())
			if !errors.Is(err, appmcp.ErrSubscriptionProtocol) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestModernSubscriptionSSEDecodesFragmentedCRLFMultilineAndComments(t *testing.T) {
	t.Parallel()
	data := "{\"jsonrpc\":\"2.0\",\n\"method\":\"notifications/tools/list_changed\",\"params\":{}}"
	input := ": keepalive\r\n\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"method\":\"notifications/tools/list_changed\",\"params\":{}}\r\n\r\n"
	body := &byteReadCloser{data: []byte(input)}
	stream := &modernSubscriptionStream{
		body:          body,
		reader:        bufio.NewReaderSize(body, 4),
		maxEventBytes: len(data),
		idleTimeout:   time.Second,
	}
	event, err := stream.Next(context.Background())
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if event.Kind != appmcp.NotificationToolsListChanged {
		t.Fatalf("event = %+v", event)
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, appmcp.ErrSubscriptionTerminal) {
		t.Fatalf("EOF error = %v", err)
	}
}

func TestModernSubscriptionSSECommentsCannotExtendIdleLifetime(t *testing.T) {
	t.Parallel()
	reader, writer := io.Pipe()
	stream := &modernSubscriptionStream{
		body:          reader,
		reader:        bufio.NewReaderSize(reader, 8),
		maxEventBytes: 128,
		idleTimeout:   30 * time.Millisecond,
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := io.WriteString(writer, ": keepalive\n\n"); err != nil {
				return
			}
		}
	}()
	started := time.Now()
	_, err := stream.Next(context.Background())
	if !errors.Is(err, appmcp.ErrSubscriptionIdle) {
		t.Fatalf("error = %v, want %v", err, appmcp.ErrSubscriptionIdle)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("comment-only stream exceeded idle bound: %s", elapsed)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	<-writerDone
}

func TestModernSubscriptionSSEEnforcesAccumulatedDataBytesBeforeDecode(t *testing.T) {
	t.Parallel()
	for _, extra := range []int{0, 1} {
		extra := extra
		t.Run(fmt.Sprintf("extra_%d", extra), func(t *testing.T) {
			t.Parallel()
			data := "12345678" + strings.Repeat("x", extra)
			body := &byteReadCloser{data: []byte("data: " + data + "\n\n")}
			stream := &modernSubscriptionStream{
				body:          body,
				reader:        bufio.NewReaderSize(body, 2),
				maxEventBytes: 8,
				idleTimeout:   time.Second,
			}
			frame, hasData, err := stream.readFrame(context.Background())
			if extra == 0 {
				if err != nil || !hasData || string(frame) != data {
					t.Fatalf("frame = %q, hasData = %t, error = %v", frame, hasData, err)
				}
				return
			}
			if !errors.Is(err, appmcp.ErrSubscriptionProtocol) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestModernSubscriptionSSECancellationUnblocksNext(t *testing.T) {
	t.Parallel()
	reader, writer := io.Pipe()
	defer writer.Close()
	stream := &modernSubscriptionStream{
		body:          reader,
		reader:        bufio.NewReaderSize(reader, 8),
		maxEventBytes: 128,
		idleTimeout:   time.Minute,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := stream.Next(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestModernSubscriptionSSEDoesNotDispatchUnterminatedEvent(t *testing.T) {
	t.Parallel()
	body := &byteReadCloser{data: []byte(
		`data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`,
	)}
	stream := &modernSubscriptionStream{
		body:          body,
		reader:        bufio.NewReaderSize(body, 4),
		maxEventBytes: 1024,
		idleTimeout:   time.Second,
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, appmcp.ErrSubscriptionTerminal) {
		t.Fatalf("error = %v", err)
	}
}

func TestDecodeSubscriptionEventAllowsOnlyListChangedTrio(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method string
		kind   appmcp.NotificationKind
	}{
		{method: "notifications/tools/list_changed", kind: appmcp.NotificationToolsListChanged},
		{method: "notifications/prompts/list_changed", kind: appmcp.NotificationPromptsListChanged},
		{method: "notifications/resources/list_changed", kind: appmcp.NotificationResourcesListChanged},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.kind), func(t *testing.T) {
			t.Parallel()
			event, terminal, err := decodeSubscriptionEvent([]byte(mustJSON(map[string]any{
				"jsonrpc": "2.0",
				"method":  test.method,
				"params":  map[string]any{},
			})))
			if err != nil || terminal || event.Kind != test.kind {
				t.Fatalf("event = %+v, terminal = %t, error = %v", event, terminal, err)
			}
		})
	}
}

func TestModernSubscriptionStreamIdleTimeoutAndCancellation(t *testing.T) {
	t.Parallel()
	capabilities := appmcp.ListChangedCapabilities{Tools: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSEData(t, w, subscriptionAck(capabilities))
		<-r.Context().Done()
	}))
	defer server.Close()
	target := appmcp.Target{URL: server.URL, RegistryTargetID: "registry", Headers: map[string]string{}}
	connector, prepared := testSubscriptionConnector(t, server, target, capabilities, 30*time.Millisecond, 1024)
	stream, err := connector.Open(context.Background(), target, prepared)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer stream.Close()
	_, err = stream.Next(context.Background())
	if !errors.Is(err, appmcp.ErrSubscriptionIdle) {
		t.Fatalf("idle error = %v", err)
	}
}

func TestModernSubscriptionOpenClassifiesAuthenticationFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	capabilities := appmcp.ListChangedCapabilities{Tools: true}
	target := appmcp.Target{URL: server.URL, RegistryTargetID: "registry", Headers: map[string]string{}}
	connector, prepared := testSubscriptionConnector(t, server, target, capabilities, time.Second, 1024)
	_, err := connector.Open(context.Background(), target, prepared)
	if !errors.Is(err, appmcp.ErrSubscriptionAuthentication) {
		t.Fatalf("error = %v", err)
	}
}

func testSubscriptionConnector(
	t *testing.T,
	server *httptest.Server,
	target appmcp.Target,
	capabilities appmcp.ListChangedCapabilities,
	idleTimeout time.Duration,
	maxEventBytes int,
) (*modernSubscriptionConnector, appmcp.PreparedSubscription) {
	t.Helper()
	key, err := subscriptionSourceKey(target, capabilities)
	if err != nil {
		t.Fatalf("source key: %v", err)
	}
	return &modernSubscriptionConnector{
		probe:         subscriptionProbeResult{},
		transport:     server.Client().Transport,
		maxEventBytes: maxEventBytes,
		idleTimeout:   idleTimeout,
	}, appmcp.PreparedSubscription{Key: key, Capabilities: capabilities}
}

func subscriptionAck(capabilities appmcp.ListChangedCapabilities) string {
	raw, err := subscriptionListenBody(capabilities)
	if err != nil {
		panic(err)
	}
	var request map[string]any
	if err := json.Unmarshal(raw, &request); err != nil {
		panic(err)
	}
	request["method"] = "notifications/subscriptions/acknowledged"
	delete(request, "id")
	return mustJSON(request)
}

func mustJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func writeSSEData(t *testing.T, w http.ResponseWriter, data string) {
	t.Helper()
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		t.Errorf("write SSE: %v", err)
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}
