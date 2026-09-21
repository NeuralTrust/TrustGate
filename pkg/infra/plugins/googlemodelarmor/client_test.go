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

package googlemodelarmor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func staticTokenSource(token string, err error) tokenSource {
	return func(context.Context) (string, error) {
		return token, err
	}
}

func TestSanitizeUserPromptRoundTrip(t *testing.T) {
	t.Parallel()

	var gotPath, gotAuth, gotContentType string
	var gotBody sanitizeUserPromptRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if got := r.Method; got != http.MethodPost {
			t.Errorf("method = %q, want %q", got, http.MethodPost)
		}
		if got := r.URL.RawQuery; got != "" {
			t.Errorf("query = %q, want empty", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		_, _ = io.WriteString(w, `{"sanitizationResult":{
			"filterMatchState":"MATCH_FOUND",
			"invocationResult":"SUCCESS",
			"filterResults":{
				"sdp":{"sdpFilterResult":{"deidentifyResult":{"matchState":"MATCH_FOUND","data":{"text":"redacted"},"infoTypes":["EMAIL_ADDRESS"],"transformedBytes":"24"}}},
				"pi_and_jailbreak":{"piAndJailbreakFilterResult":{"matchState":"NO_MATCH_FOUND","confidenceLevel":"LOW"}}
			}
		}}`)
	}))
	defer srv.Close()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("minted-token", nil))
	result, err := c.SanitizeUserPrompt(context.Background(), "proj", "us-central1", "tmpl-1", "hello there")
	if err != nil {
		t.Fatalf("SanitizeUserPrompt returned error: %v", err)
	}

	if gotAuth != "Bearer minted-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer minted-token")
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", gotContentType, "application/json")
	}
	wantPath := "/v1/projects/proj/locations/us-central1/templates/tmpl-1:sanitizeUserPrompt"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotBody.UserPromptData.Text != "hello there" {
		t.Errorf("userPromptData.text = %q, want %q", gotBody.UserPromptData.Text, "hello there")
	}

	if result.FilterMatchState != "MATCH_FOUND" {
		t.Errorf("filterMatchState = %q, want MATCH_FOUND", result.FilterMatchState)
	}
	if result.InvocationResult != "SUCCESS" {
		t.Errorf("invocationResult = %q, want SUCCESS", result.InvocationResult)
	}
	if result.FilterResults.SDP == nil || result.FilterResults.SDP.SdpFilterResult.DeidentifyResult == nil {
		t.Fatal("expected sdp.deidentifyResult to be decoded")
	}
	if got := result.FilterResults.SDP.SdpFilterResult.DeidentifyResult.Data.Text; got != "redacted" {
		t.Errorf("sdp deidentified text = %q, want %q", got, "redacted")
	}
	if got := result.FilterResults.SDP.SdpFilterResult.DeidentifyResult.InfoTypes; len(got) != 1 || got[0] != "EMAIL_ADDRESS" {
		t.Errorf("sdp infoTypes = %v, want [EMAIL_ADDRESS]", got)
	}
	if result.FilterResults.PIAndJailbreak == nil || result.FilterResults.PIAndJailbreak.PiAndJailbreakFilterResult == nil {
		t.Fatal("expected pi_and_jailbreak.piAndJailbreakFilterResult to be decoded")
	}
	if got := result.FilterResults.PIAndJailbreak.PiAndJailbreakFilterResult.ConfidenceLevel; got != "LOW" {
		t.Errorf("pi_and_jailbreak confidenceLevel = %q, want LOW", got)
	}
}

func TestSanitizeModelResponseRoundTrip(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody sanitizeModelResponseRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		_, _ = io.WriteString(w, `{"sanitizationResult":{"filterMatchState":"NO_MATCH_FOUND","invocationResult":"SUCCESS","filterResults":{}}}`)
	}))
	defer srv.Close()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("minted-token", nil))
	result, err := c.SanitizeModelResponse(context.Background(), "proj", "europe-west4", "tmpl-2", "the answer", "what is it?")
	if err != nil {
		t.Fatalf("SanitizeModelResponse returned error: %v", err)
	}

	wantPath := "/v1/projects/proj/locations/europe-west4/templates/tmpl-2:sanitizeModelResponse"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotBody.ModelResponseData.Text != "the answer" {
		t.Errorf("modelResponseData.text = %q, want %q", gotBody.ModelResponseData.Text, "the answer")
	}
	if gotBody.UserPrompt != "what is it?" {
		t.Errorf("userPrompt = %q, want %q", gotBody.UserPrompt, "what is it?")
	}
	if result.FilterMatchState != "NO_MATCH_FOUND" {
		t.Errorf("filterMatchState = %q, want NO_MATCH_FOUND", result.FilterMatchState)
	}
}

func TestClientDefaultsToRegionalHostWhenBaseURLEmpty(t *testing.T) {
	t.Parallel()

	c := newClientWithTokenSource("", time.Second, staticTokenSource("t", nil))
	got := c.url("proj", "asia-south1", "tmpl", actionSanitizeUserPrompt)
	want := "https://modelarmor.asia-south1.rep.googleapis.com/v1/projects/proj/locations/asia-south1/templates/tmpl:sanitizeUserPrompt"
	if got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
}

func TestClientTrimsTrailingSlashFromBaseURL(t *testing.T) {
	t.Parallel()

	c := newClientWithTokenSource("https://proxy.example/", time.Second, staticTokenSource("t", nil))
	got := c.url("proj", "us-central1", "tmpl", actionSanitizeModelResponse)
	want := "https://proxy.example/v1/projects/proj/locations/us-central1/templates/tmpl:sanitizeModelResponse"
	if got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
}

func TestNewClientAppliesDefaultTimeout(t *testing.T) {
	t.Parallel()

	c := newClient("", 0)
	if c.http.Timeout != defaultTimeout {
		t.Errorf("timeout = %s, want default %s", c.http.Timeout, defaultTimeout)
	}
}

func TestSanitizeMissingIdentifiers(t *testing.T) {
	t.Parallel()

	c := newClientWithTokenSource("https://example.invalid", time.Second, staticTokenSource("t", nil))
	tests := []struct {
		name, project, location, template string
	}{
		{"missing project", "", "us-central1", "tmpl"},
		{"missing location", "proj", "", "tmpl"},
		{"missing template", "proj", "us-central1", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := c.SanitizeUserPrompt(context.Background(), tt.project, tt.location, tt.template, "text"); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestSanitizeTokenSourceError(t *testing.T) {
	t.Parallel()

	c := newClientWithTokenSource("https://example.invalid", time.Second, staticTokenSource("", fmt.Errorf("adc unavailable")))
	_, err := c.SanitizeUserPrompt(context.Background(), "proj", "us-central1", "tmpl", "text")
	if err == nil || !strings.Contains(err.Error(), "acquiring bearer token") {
		t.Fatalf("err = %v, want it to mention acquiring bearer token", err)
	}
}

func TestSanitizeNonOKStatus(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"permission denied"}`)
	}))
	defer srv.Close()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("t", nil))
	_, err := c.SanitizeUserPrompt(context.Background(), "proj", "us-central1", "tmpl", "text")
	if err == nil || !strings.Contains(err.Error(), "unexpected status 403") {
		t.Fatalf("err = %v, want it to mention status 403", err)
	}
}

func TestSanitizeMalformedResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{not json`)
	}))
	defer srv.Close()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("t", nil))
	_, err := c.SanitizeUserPrompt(context.Background(), "proj", "us-central1", "tmpl", "text")
	if err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("err = %v, want it to mention decode response", err)
	}
}

func TestSanitizeTransportError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("t", nil))
	if _, err := c.SanitizeUserPrompt(context.Background(), "proj", "us-central1", "tmpl", "text"); err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

func TestSanitizeContextCanceled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"sanitizationResult":{}}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("t", nil))
	if _, err := c.SanitizeUserPrompt(ctx, "proj", "us-central1", "tmpl", "text"); err == nil {
		t.Fatal("expected context error, got nil")
	}
}

// TestSanitizeDecodesRAIMaliciousURIsAndCSAM round-trips real Model Armor
// JSON (field names verified against Google's REST reference) through
// json.Unmarshal, unlike the assess_test.go table tests which construct Go
// structs directly and so never exercise the `json:"..."` tags themselves.
func TestSanitizeDecodesRAIMaliciousURIsAndCSAM(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"sanitizationResult":{
			"filterMatchState":"MATCH_FOUND",
			"invocationResult":"SUCCESS",
			"filterResults":{
				"rai":{"raiFilterResult":{"matchState":"MATCH_FOUND","raiFilterTypeResults":{"hate_speech":{"matchState":"MATCH_FOUND","confidenceLevel":"HIGH"}}}},
				"malicious_uris":{"maliciousUriFilterResult":{"matchState":"MATCH_FOUND","maliciousUriMatchedItems":[{"uri":"http://evil.example/payload"}]}},
				"csam":{"csamFilterFilterResult":{"matchState":"MATCH_FOUND"}}
			}
		}}`)
	}))
	defer srv.Close()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("t", nil))
	result, err := c.SanitizeUserPrompt(context.Background(), "proj", "us-central1", "tmpl", "text")
	if err != nil {
		t.Fatalf("SanitizeUserPrompt returned error: %v", err)
	}

	if result.FilterResults.RAI == nil || result.FilterResults.RAI.RaiFilterResult == nil {
		t.Fatal("expected rai.raiFilterResult to be decoded")
	}
	if got := result.FilterResults.RAI.RaiFilterResult.MatchState; got != "MATCH_FOUND" {
		t.Errorf("rai matchState = %q, want MATCH_FOUND", got)
	}
	hate, ok := result.FilterResults.RAI.RaiFilterResult.RaiFilterTypeResults["hate_speech"]
	if !ok {
		t.Fatal("expected raiFilterTypeResults[hate_speech] to be decoded")
	}
	if hate.ConfidenceLevel != "HIGH" {
		t.Errorf("hate_speech confidenceLevel = %q, want HIGH", hate.ConfidenceLevel)
	}

	if result.FilterResults.MaliciousURIs == nil || result.FilterResults.MaliciousURIs.MaliciousURIFilterResult == nil {
		t.Fatal("expected malicious_uris.maliciousUriFilterResult to be decoded")
	}
	mu := result.FilterResults.MaliciousURIs.MaliciousURIFilterResult
	if mu.MatchState != "MATCH_FOUND" {
		t.Errorf("malicious_uris matchState = %q, want MATCH_FOUND", mu.MatchState)
	}
	if len(mu.MatchedItems) != 1 || mu.MatchedItems[0].URI != "http://evil.example/payload" {
		t.Errorf("maliciousUriMatchedItems = %+v, want one item with the stub URI", mu.MatchedItems)
	}

	if result.FilterResults.CSAM == nil || result.FilterResults.CSAM.CSAMFilterFilterResult == nil {
		t.Fatal("expected csam.csamFilterFilterResult to be decoded")
	}
	if got := result.FilterResults.CSAM.CSAMFilterFilterResult.MatchState; got != "MATCH_FOUND" {
		t.Errorf("csam matchState = %q, want MATCH_FOUND", got)
	}
}

// TestSanitizeDecodesInspectOnlySDP pins the shape a template configured with
// an inspect template but no de-identify template returns. Model Armor then
// reports inspectResult and never deidentifyResult, so a decoder that only
// models the latter sees no sensitive-data match at all — detection silently
// off, not merely anonymization.
func TestSanitizeDecodesInspectOnlySDP(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"sanitizationResult":{
			"filterMatchState":"MATCH_FOUND",
			"invocationResult":"SUCCESS",
			"filterResults":{
				"sdp":{"sdpFilterResult":{"inspectResult":{"matchState":"MATCH_FOUND","infoTypes":["EMAIL_ADDRESS"]}}}
			}
		}}`)
	}))
	defer srv.Close()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("minted-token", nil))
	result, err := c.SanitizeUserPrompt(context.Background(), "proj", "europe-southwest1", "tmpl", "mail me at a@b.com")
	if err != nil {
		t.Fatalf("SanitizeUserPrompt returned error: %v", err)
	}

	sdp := result.sdp()
	if sdp == nil || sdp.InspectResult == nil {
		t.Fatal("expected sdp.sdpFilterResult.inspectResult to be decoded")
	}
	if got := sdp.InspectResult.MatchState; got != matchStateMatchFound {
		t.Errorf("inspectResult matchState = %q, want %q", got, matchStateMatchFound)
	}
	if got := sdp.InspectResult.InfoTypes; len(got) != 1 || got[0] != "EMAIL_ADDRESS" {
		t.Errorf("inspectResult infoTypes = %v, want [EMAIL_ADDRESS]", got)
	}
	if sdp.DeidentifyResult != nil {
		t.Error("inspect-only template must not produce a deidentifyResult")
	}
}

// TestSanitizeErrorOmitsResponseBody guards the containment property the
// guardrail exists for: a Model Armor error body can echo back SDP findings
// and de-identified text, and an error string ends up in logs.
func TestSanitizeErrorOmitsResponseBody(t *testing.T) {
	t.Parallel()

	const leaked = "sergi.vidal@example.com"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"bad template, found `+leaked+`"}}`)
	}))
	defer srv.Close()

	c := newClientWithTokenSource(srv.URL, time.Second, staticTokenSource("minted-token", nil))
	_, err := c.SanitizeUserPrompt(context.Background(), "proj", "europe-southwest1", "tmpl", "hi")
	if err == nil {
		t.Fatal("expected an error for a 400 response")
	}
	if strings.Contains(err.Error(), leaked) {
		t.Errorf("error leaks the upstream body: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should still name the status, got %q", err.Error())
	}
}
