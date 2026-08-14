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
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

type legacyRoundTripFunc func(*http.Request) (*http.Response, error)

func (f legacyRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackedRequestBody struct {
	reader io.Reader
	closes *atomic.Int64
}

func (b *trackedRequestBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *trackedRequestBody) Close() error {
	b.closes.Add(1)
	return nil
}

func newTrackedRequest(t *testing.T, method, contentType string, data []byte) (*http.Request, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	req, err := http.NewRequest(method, "https://upstream.example/mcp", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	var bodyCloses atomic.Int64
	var peekCloses atomic.Int64
	req.Body = &trackedRequestBody{reader: bytes.NewReader(data), closes: &bodyCloses}
	req.GetBody = func() (io.ReadCloser, error) {
		return &trackedRequestBody{reader: bytes.NewReader(data), closes: &peekCloses}, nil
	}
	req.Header.Set("Content-Type", contentType)
	return req, &bodyCloses, &peekCloses
}

func TestLegacyDiscoverRoundTripper_PreservesJSONRPCIDLocally(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
	}{
		{name: "numeric", id: "17"},
		{name: "string", id: `"request-17"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var delegateCalls atomic.Int64
			transport := newLegacyDiscoverRoundTripper(legacyRoundTripFunc(func(*http.Request) (*http.Response, error) {
				delegateCalls.Add(1)
				return nil, nil
			}))
			body := []byte(`{"jsonrpc":"2.0","id":` + tt.id + `,"method":"server/discover","params":{}}`)
			req, bodyCloses, peekCloses := newTrackedRequest(
				t, http.MethodPost, "application/json", body)

			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			defer resp.Body.Close()
			if delegateCalls.Load() != 0 {
				t.Fatalf("delegate calls = %d, want 0", delegateCalls.Load())
			}
			if bodyCloses.Load() != 1 {
				t.Fatalf("request body closes = %d, want 1", bodyCloses.Load())
			}
			if peekCloses.Load() != 1 {
				t.Fatalf("peek body closes = %d, want 1", peekCloses.Load())
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("content type = %q, want application/json", got)
			}
			var envelope struct {
				ID    json.RawMessage `json:"id"`
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if string(envelope.ID) != tt.id {
				t.Fatalf("response id = %s, want %s", envelope.ID, tt.id)
			}
			if envelope.Error.Code != -32601 {
				t.Fatalf("error code = %d, want -32601", envelope.Error.Code)
			}
		})
	}
}

func TestLegacyDiscoverRoundTripper_DelegatesOtherRequestsUnchanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		httpMethod  string
		rpcMethod   string
		contentType string
	}{
		{
			name:        "case-sensitive method",
			httpMethod:  http.MethodPost,
			rpcMethod:   "Server/Discover",
			contentType: "application/json",
		},
		{
			name:        "non-POST",
			httpMethod:  http.MethodPut,
			rpcMethod:   methodServerDiscover,
			contentType: "application/json",
		},
		{
			name:        "non-JSON",
			httpMethod:  http.MethodPost,
			rpcMethod:   methodServerDiscover,
			contentType: "text/plain",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"` + tt.rpcMethod + `","params":{}}`)
			req, bodyCloses, peekCloses := newTrackedRequest(
				t, tt.httpMethod, tt.contentType, body)
			var delegateCalls atomic.Int64
			transport := newLegacyDiscoverRoundTripper(legacyRoundTripFunc(func(got *http.Request) (*http.Response, error) {
				delegateCalls.Add(1)
				if got != req {
					t.Fatalf("delegated request pointer changed")
				}
				if bodyCloses.Load() != 0 {
					t.Fatalf("request body closed before delegation")
				}
				gotBody, err := io.ReadAll(got.Body)
				if err != nil {
					t.Fatalf("read delegated body: %v", err)
				}
				if !bytes.Equal(gotBody, body) {
					t.Fatalf("delegated body = %s, want %s", gotBody, body)
				}
				if err := got.Body.Close(); err != nil {
					t.Fatalf("close delegated body: %v", err)
				}
				return &http.Response{
					StatusCode: http.StatusAccepted,
					Header:     make(http.Header),
					Body:       http.NoBody,
					Request:    got,
				}, nil
			}))

			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			defer resp.Body.Close()
			if delegateCalls.Load() != 1 {
				t.Fatalf("delegate calls = %d, want 1", delegateCalls.Load())
			}
			if bodyCloses.Load() != 1 {
				t.Fatalf("delegated body closes = %d, want 1", bodyCloses.Load())
			}
			wantPeekCloses := int64(0)
			if tt.httpMethod == http.MethodPost && tt.contentType == "application/json" {
				wantPeekCloses = 1
			}
			if peekCloses.Load() != wantPeekCloses {
				t.Fatalf("peek body closes = %d, want %d", peekCloses.Load(), wantPeekCloses)
			}
			if resp.StatusCode != http.StatusAccepted {
				t.Fatalf("status = %d, want 202", resp.StatusCode)
			}
		})
	}
}

func TestLegacyDiscoverRoundTripper_InterceptsExactBodyLimit(t *testing.T) {
	t.Parallel()

	prefix := []byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"padding":"`)
	suffix := []byte(`"}}`)
	padding := bytes.Repeat(
		[]byte("x"),
		maxLegacyDiscoverRequestBodyBytes-len(prefix)-len(suffix),
	)
	body := append(prefix, padding...)
	body = append(body, suffix...)
	if len(body) != maxLegacyDiscoverRequestBodyBytes {
		t.Fatalf("request body length = %d, want %d", len(body), maxLegacyDiscoverRequestBodyBytes)
	}
	req, bodyCloses, peekCloses := newTrackedRequest(
		t, http.MethodPost, "application/json", body)
	var delegateCalls atomic.Int64
	transport := newLegacyDiscoverRoundTripper(legacyRoundTripFunc(func(*http.Request) (*http.Response, error) {
		delegateCalls.Add(1)
		return nil, nil
	}))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if delegateCalls.Load() != 0 {
		t.Fatalf("delegate calls = %d, want 0", delegateCalls.Load())
	}
	if bodyCloses.Load() != 1 {
		t.Fatalf("request body closes = %d, want 1", bodyCloses.Load())
	}
	if peekCloses.Load() != 1 {
		t.Fatalf("peek body closes = %d, want 1", peekCloses.Load())
	}
}

func TestLegacyDiscoverRoundTripper_DelegatesOversizedBodyUnchanged(t *testing.T) {
	t.Parallel()

	padding := bytes.Repeat([]byte("x"), maxProbeBodyBytes)
	body := append([]byte(`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"padding":"`), padding...)
	body = append(body, `"}}`...)
	req, bodyCloses, peekCloses := newTrackedRequest(
		t, http.MethodPost, "application/json", body)
	var delegateCalls atomic.Int64
	transport := newLegacyDiscoverRoundTripper(legacyRoundTripFunc(func(got *http.Request) (*http.Response, error) {
		delegateCalls.Add(1)
		if got != req {
			t.Fatal("oversized delegated request pointer changed")
		}
		if bodyCloses.Load() != 0 {
			t.Fatal("request body closed before oversized delegation")
		}
		gotBody, err := io.ReadAll(got.Body)
		if err != nil {
			t.Fatalf("read delegated body: %v", err)
		}
		if !bytes.Equal(gotBody, body) {
			t.Fatalf("delegated body length = %d, want %d", len(gotBody), len(body))
		}
		if err := got.Body.Close(); err != nil {
			t.Fatalf("close delegated body: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    got,
		}, nil
	}))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if delegateCalls.Load() != 1 {
		t.Fatalf("delegate calls = %d, want 1", delegateCalls.Load())
	}
	if bodyCloses.Load() != 1 {
		t.Fatalf("delegated body closes = %d, want 1", bodyCloses.Load())
	}
	if peekCloses.Load() != 1 {
		t.Fatalf("peek body closes = %d, want 1", peekCloses.Load())
	}
}
