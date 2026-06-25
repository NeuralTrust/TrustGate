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

package azurecontentsafety

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func sampleRequest() analyzeRequest {
	return analyzeRequest{
		Text:       "hello world",
		Categories: []string{CategoryHate, CategoryViolence},
		OutputType: OutputTypeFourSeverityLevels,
	}
}

func TestAnalyzeDecodesResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		statusCode   int
		respBody     string
		wantErr      bool
		wantCount    int
		wantSeverity int
	}{
		{
			name:         "categories analysis decoded",
			statusCode:   http.StatusOK,
			respBody:     `{"categoriesAnalysis":[{"category":"Hate","severity":4},{"category":"Violence","severity":0}]}`,
			wantCount:    2,
			wantSeverity: 4,
		},
		{
			name:       "empty analysis",
			statusCode: http.StatusOK,
			respBody:   `{"categoriesAnalysis":[]}`,
			wantCount:  0,
		},
		{
			name:       "non-2xx",
			statusCode: http.StatusTooManyRequests,
			respBody:   `{"error":"throttled"}`,
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
				if got := r.Method; got != http.MethodPost {
					t.Errorf("method = %q, want %q", got, http.MethodPost)
				}
				if got := r.Header.Get("Ocp-Apim-Subscription-Key"); got != "secret-key" {
					t.Errorf("subscription key header = %q, want %q", got, "secret-key")
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("content-type header = %q, want %q", got, "application/json")
				}
				var got analyzeRequest
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode request body: %v", err)
				}
				if got.Text != "hello world" {
					t.Errorf("text = %q, want %q", got.Text, "hello world")
				}
				if len(got.Categories) != 2 {
					t.Errorf("categories = %v, want 2 entries", got.Categories)
				}
				if got.OutputType != OutputTypeFourSeverityLevels {
					t.Errorf("outputType = %q, want %q", got.OutputType, OutputTypeFourSeverityLevels)
				}
				w.WriteHeader(tt.statusCode)
				_, _ = io.WriteString(w, tt.respBody)
			}))
			defer srv.Close()

			c := newClient()
			resp, err := c.Analyze(context.Background(), srv.URL, "secret-key", sampleRequest())
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Analyze returned error: %v", err)
			}
			if len(resp.CategoriesAnalysis) != tt.wantCount {
				t.Errorf("categoriesAnalysis = %d, want %d", len(resp.CategoriesAnalysis), tt.wantCount)
			}
			if tt.wantCount > 0 && resp.CategoriesAnalysis[0].Severity != tt.wantSeverity {
				t.Errorf("severity = %d, want %d", resp.CategoriesAnalysis[0].Severity, tt.wantSeverity)
			}
		})
	}
}

func TestAnalyzeTransportError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	c := newClient()
	if _, err := c.Analyze(context.Background(), srv.URL, "k", sampleRequest()); err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

func TestAnalyzeContextCanceled(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"categoriesAnalysis":[]}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := newClient()
	if _, err := c.Analyze(ctx, srv.URL, "k", sampleRequest()); err == nil {
		t.Fatal("expected context error, got nil")
	}
}
