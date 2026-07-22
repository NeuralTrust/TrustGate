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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func openAIRequestBody() []byte {
	return []byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"be safe"},{"role":"user","content":"hello world"}]}`)
}

func emptyRequestBody() []byte {
	return []byte(`{"model":"gpt-4o","messages":[]}`)
}

func requestContext(body []byte) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Provider:       "openai",
		SourceFormat:   "openai",
		SessionID:      "sess-123",
		RequestedModel: "gpt-4o-mini",
		Body:           body,
	}
}

func settings(endpoint string, severity map[string]int) map[string]any {
	thresholds := make(map[string]any, len(severity))
	for category, value := range severity {
		thresholds[category] = value
	}
	return map[string]any{
		"api_key":           "secret-key",
		"endpoint":          endpoint,
		"output_type":       OutputTypeFourSeverityLevels,
		"category_severity": thresholds,
	}
}

func execInput(stage policy.Stage, mode policy.Mode, set map[string]any, req *infracontext.RequestContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:   stage,
		Mode:    mode,
		Config:  policy.PluginConfig{Settings: set},
		Request: req,
	}
}

type fakeAzure struct {
	mu       sync.Mutex
	hits     int
	lastBody analyzeRequest
	status   int
	response analyzeResponse
}

func (f *fakeAzure) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		var body analyzeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.lastBody = body
		status := f.status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(f.response)
	}
}

func (f *fakeAzure) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

func newServer(t *testing.T, f *fakeAzure) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestExecuteEnforceBlockReturns403(t *testing.T) {
	t.Parallel()

	f := &fakeAzure{response: analyzeResponse{CategoriesAnalysis: []categoryAnalysis{
		{Category: CategoryHate, Severity: 4},
		{Category: CategoryViolence, Severity: 6},
	}}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), nil)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(openAIRequestBody()))
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on block, got %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", pe.StatusCode, http.StatusForbidden)
	}
	if ct := pe.Headers["Content-Type"]; len(ct) != 1 || ct[0] != "application/json" {
		t.Fatalf("Content-Type header = %v, want [application/json]", ct)
	}
	if pe.Type != typeContentFlagged {
		t.Fatalf("type = %q, want %q", pe.Type, typeContentFlagged)
	}
	var decoded struct {
		Error struct {
			Type       string             `json:"type"`
			Message    string             `json:"message"`
			Categories []breachedCategory `json:"categories"`
		} `json:"error"`
	}
	if err := json.Unmarshal(pe.Body, &decoded); err != nil {
		t.Fatalf("decode block body: %v", err)
	}
	if decoded.Error.Type != typeContentFlagged {
		t.Fatalf("body type = %q, want %q", decoded.Error.Type, typeContentFlagged)
	}
	if len(decoded.Error.Categories) != 1 {
		t.Fatalf("categories = %+v, want only breached", decoded.Error.Categories)
	}
	if decoded.Error.Categories[0].Category != CategoryHate || decoded.Error.Categories[0].Severity != 4 || decoded.Error.Categories[0].Threshold != 2 {
		t.Fatalf("breached = %+v, want Hate/4/2", decoded.Error.Categories[0])
	}
	if f.lastBody.Text != "be safe\nhello world" {
		t.Fatalf("text = %q, want %q", f.lastBody.Text, "be safe\nhello world")
	}
}

func TestExecuteObserveModeOnBreachPassesThrough(t *testing.T) {
	t.Parallel()

	f := &fakeAzure{response: analyzeResponse{CategoriesAnalysis: []categoryAnalysis{
		{Category: CategoryHate, Severity: 6},
	}}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), nil)

	in := execInput(policy.StagePreRequest, policy.ModeObserve, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(openAIRequestBody()))
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("observe mode must not error, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
		t.Fatalf("expected pass-through in observe mode, got %+v", res)
	}
	if f.count() != 1 {
		t.Fatalf("expected azure called once, got %d", f.count())
	}
}

func TestExecuteEmptyTextPassThrough(t *testing.T) {
	t.Parallel()

	f := &fakeAzure{}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), nil)

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(emptyRequestBody()))
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through, got %+v", res)
	}
	if f.count() != 0 {
		t.Fatalf("expected azure not called for empty text, got %d hits", f.count())
	}
}

func TestExecuteAzureErrorEnforceReturnsError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()

	p := New(adapter.NewRegistry(), nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings(addr, map[string]int{CategoryHate: 2}), requestContext(openAIRequestBody()))
	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on fail-closed, got %+v", res)
	}
	if err == nil {
		t.Fatal("expected error on azure failure in enforce mode")
		return
	}
	if _, ok := appplugins.AsPluginError(err); ok {
		t.Fatalf("expected non-PluginError on transport failure, got %v", err)
	}
}

func TestExecuteAzureErrorObservePassesThrough(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()

	p := New(adapter.NewRegistry(), nil)
	in := execInput(policy.StagePreRequest, policy.ModeObserve, settings(addr, map[string]int{CategoryHate: 2}), requestContext(openAIRequestBody()))
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("expected fail-open pass in observe mode, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK || res.StopUpstream {
		t.Fatalf("expected pass-through on azure error in observe mode, got %+v", res)
	}
}

func TestExecuteStageNotPreRequestPassThrough(t *testing.T) {
	t.Parallel()

	f := &fakeAzure{response: analyzeResponse{CategoriesAnalysis: []categoryAnalysis{
		{Category: CategoryHate, Severity: 6},
	}}}
	srv := newServer(t, f)
	p := New(adapter.NewRegistry(), nil)

	in := execInput(policy.StagePreResponse, policy.ModeEnforce, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(openAIRequestBody()))
	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK {
		t.Fatalf("expected pass-through, got %+v", res)
	}
	if f.count() != 0 {
		t.Fatalf("expected azure not called when stage not selected, got %d hits", f.count())
	}
}
