// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

func TestModernSubscriptionsOpenRejectsInvalidResponseContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      int
		contentType string
		first       string
		wantErr     error
	}{
		{
			name:        "unsupported status",
			status:      http.StatusNotFound,
			contentType: "application/json",
			wantErr:     appmcp.ErrSubscriptionTerminal,
		},
		{
			name:        "unsupported content type",
			status:      http.StatusOK,
			contentType: "application/json",
			wantErr:     appmcp.ErrSubscriptionProtocol,
		},
		{
			name:        "missing acknowledgement",
			status:      http.StatusOK,
			contentType: "text/event-stream",
			first:       `{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}`,
			wantErr:     appmcp.ErrSubscriptionProtocol,
		},
		{
			name:        "malformed acknowledgement",
			status:      http.StatusOK,
			contentType: "text/event-stream",
			first:       `{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"notifications":"tools"}}`,
			wantErr:     appmcp.ErrSubscriptionProtocol,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				if test.first != "" {
					writeSSEData(t, w, test.first)
				}
			}))
			defer server.Close()
			capabilities := appmcp.ListChangedCapabilities{Tools: true}
			target := appmcp.Target{URL: server.URL, RegistryTargetID: "registry", Headers: map[string]string{}}
			connector, prepared := testSubscriptionConnector(t, server, target, capabilities, time.Second, 1024)
			_, err := connector.Open(context.Background(), target, prepared)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestModernSubscriptionsClassifiesCleanTerminalAndTransportClose(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		trailer string
		wantErr error
	}{
		{
			name:    "unexpected result",
			trailer: `{"jsonrpc":"2.0","id":"trustgate-subscription","result":{}}`,
			wantErr: appmcp.ErrSubscriptionProtocol,
		},
		{
			name:    "clean terminal",
			wantErr: appmcp.ErrSubscriptionTerminal,
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
				if test.trailer != "" {
					writeSSEData(t, w, test.trailer)
				}
			}))
			defer server.Close()
			target := appmcp.Target{URL: server.URL, RegistryTargetID: "registry", Headers: map[string]string{}}
			connector, prepared := testSubscriptionConnector(t, server, target, capabilities, time.Second, 1024)
			stream, err := connector.Open(context.Background(), target, prepared)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer stream.Close()
			_, err = stream.Next(context.Background())
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}

	body := &subscriptionFailingReadCloser{err: io.ErrUnexpectedEOF}
	stream := &modernSubscriptionStream{
		body:          body,
		reader:        bufio.NewReader(body),
		maxEventBytes: 1024,
		idleTimeout:   time.Second,
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, appmcp.ErrSubscriptionTransportClosed) {
		t.Fatalf("Next() transport error = %v, want %v", err, appmcp.ErrSubscriptionTransportClosed)
	}
}

func TestModernSubscriptionsCloseIsIdempotentAndCancelsRequest(t *testing.T) {
	t.Parallel()
	capabilities := appmcp.ListChangedCapabilities{Tools: true}
	requestDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSEData(t, w, subscriptionAck(capabilities))
		<-r.Context().Done()
		close(requestDone)
	}))
	defer server.Close()
	target := appmcp.Target{URL: server.URL, RegistryTargetID: "registry", Headers: map[string]string{}}
	connector, prepared := testSubscriptionConnector(t, server, target, capabilities, time.Second, 1024)
	stream, err := connector.Open(context.Background(), target, prepared)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("response body close did not cancel request")
	}
}

func TestSubscriptionFailureReconnectabilityIsClosedByDefault(t *testing.T) {
	t.Parallel()
	reconnectable := []error{
		appmcp.ErrSubscriptionTransportClosed,
		appmcp.ErrSubscriptionTerminal,
		appmcp.ErrSubscriptionIdle,
	}
	for _, err := range reconnectable {
		if !appmcp.IsSubscriptionReconnectable(err) {
			t.Fatalf("%v must be reconnectable", err)
		}
	}
	terminal := []error{
		appmcp.ErrSubscriptionAuthentication,
		appmcp.ErrSubscriptionSourceChanged,
		appmcp.ErrSubscriptionProtocol,
		appmcp.ErrSubscriptionUnsupported,
	}
	for _, err := range terminal {
		if appmcp.IsSubscriptionReconnectable(err) {
			t.Fatalf("%v must be terminal", err)
		}
	}
}

type subscriptionFailingReadCloser struct {
	err error
}

func (r *subscriptionFailingReadCloser) Read([]byte) (int, error) {
	return 0, r.err
}

func (r *subscriptionFailingReadCloser) Close() error {
	return nil
}
