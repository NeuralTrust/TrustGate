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

// Package modelarmor is a REST client for Google Cloud Model Armor
// (https://cloud.google.com/security-command-center/docs/model-armor-overview).
// There is no global Model Armor endpoint: every template lives in one of 21
// regional hosts (modelarmor.{location}.rep.googleapis.com), so callers name
// project/location/template on every call rather than baking them into the
// client. This package intentionally stops at transport: sanitize/anonymize
// policy decisions (block_on handling, message building, plugin
// registration) are out of scope here and land with the plugin itself.
package modelarmor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
)

const (
	defaultTimeout   = 10 * time.Second
	maxResponseBytes = 1 << 20

	hostTemplate = "https://modelarmor.%s.rep.googleapis.com"
	apiVersion   = "v1"

	actionSanitizeUserPrompt    = "sanitizeUserPrompt"
	actionSanitizeModelResponse = "sanitizeModelResponse"
)

// tokenSource returns a bearer token to authorize a Model Armor call. It is
// injectable so tests never need real GCP credentials.
type tokenSource func(ctx context.Context) (string, error)

type client struct {
	http        *http.Client
	baseURL     string
	tokenSource tokenSource
}

// newClient builds a Model Armor REST client.
//
// baseURL overrides the regional "https://modelarmor.{location}.rep.googleapis.com"
// host when non-empty (tests, or a private egress proxy); leave it empty in
// production so each call addresses the region its own request names, since
// Model Armor has no global endpoint.
//
// Authorization defaults to Application Default Credentials / GKE Workload
// Identity, scoped to cloud-platform. There is currently no field on this
// plugin's settings to hold an explicit service-account JSON — see
// pkg/infra/providers/gcpauth's package doc for why that is a deliberate
// choice, not an oversight — so ADC is the only credential source wired up.
// A future settings field can add an explicit-credential path without
// changing this constructor's signature, since gcpauth already supports it.
func newClient(baseURL string, timeout time.Duration) *client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	adc := gcpauth.NewApplicationDefaultCache()
	return newClientWithTokenSource(baseURL, timeout, func(ctx context.Context) (string, error) {
		return adc.Token(ctx, gcpauth.CloudPlatformScope)
	})
}

func newClientWithTokenSource(baseURL string, timeout time.Duration, ts tokenSource) *client {
	return &client{
		http: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL:     strings.TrimRight(baseURL, "/"),
		tokenSource: ts,
	}
}

// SanitizationResult is the decoded `sanitizationResult` object common to
// both sanitize endpoints.
type SanitizationResult struct {
	FilterMatchState string        `json:"filterMatchState"`
	InvocationResult string        `json:"invocationResult"`
	FilterResults    FilterResults `json:"filterResults"`
}

// FilterResults holds the filter outcomes Model Armor documents today. Other
// block_on categories (rai, malicious_uris, csam) are not yet modeled here;
// json.Unmarshal drops unknown keys, so adding fields for them later is
// forward-compatible and does not require a client rewrite.
type FilterResults struct {
	SDP            *SDPFilterResult            `json:"sdp,omitempty"`
	PIAndJailbreak *PIAndJailbreakFilterResult `json:"pi_and_jailbreak,omitempty"`
}

// SDPFilterResult is the sensitive-data-protection filter outcome.
type SDPFilterResult struct {
	DeidentifyResult *SDPDeidentifyResult `json:"deidentifyResult,omitempty"`
}

// SDPDeidentifyResult carries the de-identified text Model Armor produced
// (Data.Text) when it rewrote rather than merely flagged sensitive data.
type SDPDeidentifyResult struct {
	MatchState       string   `json:"matchState"`
	Data             *SDPData `json:"data,omitempty"`
	InfoTypes        []string `json:"infoTypes,omitempty"`
	TransformedBytes string   `json:"transformedBytes,omitempty"`
}

// SDPData wraps the sanitized text returned inside an SDPDeidentifyResult.
type SDPData struct {
	Text string `json:"text"`
}

// PIAndJailbreakFilterResult is the prompt-injection / jailbreak filter outcome.
type PIAndJailbreakFilterResult struct {
	PiAndJailbreakFilterResult *PIAndJailbreakResult `json:"piAndJailbreakFilterResult,omitempty"`
}

// PIAndJailbreakResult reports the match state and Model Armor's confidence in it.
type PIAndJailbreakResult struct {
	MatchState      string `json:"matchState"`
	ConfidenceLevel string `json:"confidenceLevel"`
}

type sanitizeResponse struct {
	SanitizationResult SanitizationResult `json:"sanitizationResult"`
}

type userPromptData struct {
	Text string `json:"text"`
}

type modelResponseData struct {
	Text string `json:"text"`
}

type sanitizeUserPromptRequest struct {
	UserPromptData userPromptData `json:"userPromptData"`
}

type sanitizeModelResponseRequest struct {
	ModelResponseData modelResponseData `json:"modelResponseData"`
	UserPrompt        string            `json:"userPrompt,omitempty"`
}

// SanitizeUserPrompt calls Model Armor's sanitizeUserPrompt endpoint for text
// taken from the inbound request.
func (c *client) SanitizeUserPrompt(ctx context.Context, project, location, template, text string) (*SanitizationResult, error) {
	return c.sanitize(ctx, project, location, template, actionSanitizeUserPrompt,
		sanitizeUserPromptRequest{UserPromptData: userPromptData{Text: text}})
}

// SanitizeModelResponse calls Model Armor's sanitizeModelResponse endpoint.
// userPrompt is optional correlation context Model Armor uses to judge the
// response against the prompt that produced it; pass "" when unavailable.
func (c *client) SanitizeModelResponse(ctx context.Context, project, location, template, text, userPrompt string) (*SanitizationResult, error) {
	return c.sanitize(ctx, project, location, template, actionSanitizeModelResponse,
		sanitizeModelResponseRequest{ModelResponseData: modelResponseData{Text: text}, UserPrompt: userPrompt})
}

func (c *client) sanitize(ctx context.Context, project, location, template, action string, body any) (*SanitizationResult, error) {
	if strings.TrimSpace(project) == "" || strings.TrimSpace(location) == "" || strings.TrimSpace(template) == "" {
		return nil, fmt.Errorf("model_armor: project, location and template are required")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("model_armor: marshal request: %w", err)
	}
	token, err := c.tokenSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("model_armor: acquiring bearer token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(project, location, template, action), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("model_armor: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("model_armor: %s call: %w", action, err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("model_armor: read response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("model_armor: unexpected status %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out sanitizeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("model_armor: decode response: %w", err)
	}
	return &out.SanitizationResult, nil
}

func (c *client) url(project, location, template, action string) string {
	base := c.baseURL
	if base == "" {
		base = fmt.Sprintf(hostTemplate, location)
	}
	return fmt.Sprintf("%s/%s/projects/%s/locations/%s/templates/%s:%s",
		base, apiVersion, project, location, template, action)
}
