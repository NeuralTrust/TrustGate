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

package trustguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sampleRequest() GuardRequest {
	return GuardRequest{
		Payload:    GuardPayload{Input: "hello world"},
		Direction:  "input",
		Protocol:   "llm",
		SessionID:  "session-1",
		ConsumerID: "consumer-1",
		Attributes: GuardAttributes{
			ContentType: "application/json",
			Model:       GuardModel{Name: "gpt-4o", Provider: "openai"},
		},
	}
}

func TestGuardDecodesResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		statusCode    int
		respBody      string
		wantErr       bool
		wantStatus    string
		wantFindings  int
		wantTraceID   string
		wantRequestID string
	}{
		{
			name:          "block verdict",
			statusCode:    http.StatusOK,
			respBody:      `{"status":"block","trace_id":"t1","request_id":"r1","findings":[{"source":{"kind":"detector","plugin":"data_loss_prevention"},"signal":{"type":"pii","confidence":0.9},"outcome":{"action":"block"}}]}`,
			wantStatus:    "block",
			wantFindings:  1,
			wantTraceID:   "t1",
			wantRequestID: "r1",
		},
		{
			name:          "allow empty status",
			statusCode:    http.StatusOK,
			respBody:      `{"status":"","trace_id":"t2","request_id":"r2"}`,
			wantStatus:    "",
			wantTraceID:   "t2",
			wantRequestID: "r2",
		},
		{
			name:       "non-2xx",
			statusCode: http.StatusInternalServerError,
			respBody:   `{"status":"block"}`,
			wantErr:    true,
		},
		{
			name:       "malformed json",
			statusCode: http.StatusOK,
			respBody:   `{not json`,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != evaluatePath {
					t.Errorf("path = %q, want %q", r.URL.Path, evaluatePath)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer secret-key" {
					t.Errorf("authorization header = %q, want %q", got, "Bearer secret-key")
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("content-type header = %q, want %q", got, "application/json")
				}
				var got GuardRequest
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode request body: %v", err)
				}
				if got.Direction != "input" {
					t.Errorf("direction = %q, want %q", got.Direction, "input")
				}
				if got.ConsumerID != "consumer-1" {
					t.Errorf("consumer_id = %q, want %q", got.ConsumerID, "consumer-1")
				}
				if got.Payload.Input != "hello world" {
					t.Errorf("payload.input = %q, want %q", got.Payload.Input, "hello world")
				}
				w.WriteHeader(tt.statusCode)
				_, _ = io.WriteString(w, tt.respBody)
			}))
			defer srv.Close()

			c := newClient(2 * time.Second)
			resp, err := c.Guard(context.Background(), srv.URL, "secret-key", "", sampleRequest())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Guard returned error: %v", err)
			}
			if resp.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", resp.Status, tt.wantStatus)
			}
			if len(resp.Findings) != tt.wantFindings {
				t.Errorf("findings = %d, want %d", len(resp.Findings), tt.wantFindings)
			}
			if tt.name == "block verdict" {
				f := resp.Findings[0]
				if f.Source == nil || f.Source.Kind != "detector" || f.Source.Plugin != "data_loss_prevention" {
					t.Errorf("finding source = %+v, want detector/data_loss_prevention", f.Source)
				}
				if f.Signal == nil || f.Signal.Type != "pii" || f.Signal.Confidence != 0.9 {
					t.Errorf("finding signal = %+v, want type=pii confidence=0.9", f.Signal)
				}
				if f.Outcome == nil || f.Outcome.Action != "block" {
					t.Errorf("finding outcome = %+v, want action=block", f.Outcome)
				}
			}
			if resp.TraceID != tt.wantTraceID {
				t.Errorf("trace_id = %q, want %q", resp.TraceID, tt.wantTraceID)
			}
			if resp.RequestID != tt.wantRequestID {
				t.Errorf("request_id = %q, want %q", resp.RequestID, tt.wantRequestID)
			}
		})
	}
}

func TestGuardTrimsTrailingSlash(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != evaluatePath {
			t.Errorf("path = %q, want %q", r.URL.Path, evaluatePath)
		}
		_, _ = io.WriteString(w, `{"status":""}`)
	}))
	defer srv.Close()

	c := newClient(time.Second)
	if _, err := c.Guard(context.Background(), srv.URL+"/", "k", "", sampleRequest()); err != nil {
		t.Fatalf("Guard returned error: %v", err)
	}
}

func TestGuardTransportError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	c := newClient(time.Second)
	if _, err := c.Guard(context.Background(), srv.URL, "k", "", sampleRequest()); err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

func TestGuardUnauthorizedReturnsSentinel(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newClient(time.Second)
	_, err := c.Guard(context.Background(), srv.URL, "stale-token", "", sampleRequest())
	if !errors.Is(err, errUnauthorized) {
		t.Fatalf("err = %v, want errUnauthorized", err)
	}
}

func TestGuardRateLimitedReturnsTypedError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.Header().Set("X-RateLimit-Limit", "300")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reason", "quota")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"rate limit exceeded","reason":"quota"}`)
	}))
	defer srv.Close()

	c := newClient(time.Second)
	_, err := c.Guard(context.Background(), srv.URL, "k", "", sampleRequest())
	var limited *rateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("err = %v, want *rateLimitedError", err)
	}
	if got := limited.headers["Retry-After"]; len(got) != 1 || got[0] != "30" {
		t.Fatalf("Retry-After = %v, want [30]", got)
	}
	if got := limited.headers["X-RateLimit-Reason"]; len(got) != 1 || got[0] != "quota" {
		t.Fatalf("X-RateLimit-Reason = %v, want [quota]", got)
	}
	if !bytes.Contains(limited.body, []byte(`"reason":"quota"`)) {
		t.Fatalf("body = %s, want quota reason", limited.body)
	}
}

func TestGuardRateLimitedWithoutHeaders(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"rate limit exceeded"}`)
	}))
	defer srv.Close()

	c := newClient(time.Second)
	_, err := c.Guard(context.Background(), srv.URL, "k", "", sampleRequest())
	var limited *rateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("err = %v, want *rateLimitedError", err)
	}
	if len(limited.headers) != 0 {
		t.Fatalf("headers = %v, want empty", limited.headers)
	}
	if len(limited.body) == 0 {
		t.Fatal("expected body preserved")
	}
}

func TestGuardRateLimitedIgnoresUnrelatedHeaders(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.Header().Set("X-RateLimit-Reason", "burst")
		w.Header().Set("X-Secret-Internal", "nope")
		w.Header().Set("Set-Cookie", "session=abc")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newClient(time.Second)
	_, err := c.Guard(context.Background(), srv.URL, "k", "", sampleRequest())
	var limited *rateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("err = %v, want *rateLimitedError", err)
	}
	if _, ok := limited.headers["X-Secret-Internal"]; ok {
		t.Fatal("must not forward unrelated headers")
	}
	if _, ok := limited.headers["Set-Cookie"]; ok {
		t.Fatal("must not forward Set-Cookie")
	}
	if got := limited.headers["Retry-After"]; len(got) != 1 || got[0] != "5" {
		t.Fatalf("Retry-After = %v", got)
	}
}

func TestGuardContextCanceled(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":""}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := newClient(time.Second)
	if _, err := c.Guard(ctx, srv.URL, "k", "", sampleRequest()); err == nil {
		t.Fatal("expected context error, got nil")
	}
}

func TestGuardSetsTraceIDHeader(t *testing.T) {
	t.Parallel()
	const wantTraceID = "gateway-trace-abc123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(traceIDHeader); got != wantTraceID {
			t.Errorf("X-Trace-ID header = %q, want %q", got, wantTraceID)
		}
		_, _ = io.WriteString(w, `{"status":""}`)
	}))
	defer srv.Close()

	c := newClient(time.Second)
	if _, err := c.Guard(context.Background(), srv.URL, "k", wantTraceID, sampleRequest()); err != nil {
		t.Fatalf("Guard returned error: %v", err)
	}
}

func TestGuardOmitsTraceIDHeaderWhenEmpty(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(traceIDHeader); got != "" {
			t.Errorf("X-Trace-ID header = %q, want empty", got)
		}
		_, _ = io.WriteString(w, `{"status":""}`)
	}))
	defer srv.Close()

	c := newClient(time.Second)
	if _, err := c.Guard(context.Background(), srv.URL, "k", "", sampleRequest()); err != nil {
		t.Fatalf("Guard returned error: %v", err)
	}
}
