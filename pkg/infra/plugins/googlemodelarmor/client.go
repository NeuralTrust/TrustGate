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

// Package googlemodelarmor is a REST client for Google Cloud Model Armor
// (https://cloud.google.com/security-command-center/docs/model-armor-overview).
// There is no global Model Armor endpoint: every template lives in one of 21
// regional hosts (modelarmor.{location}.rep.googleapis.com), so callers name
// project/location/template on every call rather than baking them into the
// client. This package intentionally stops at transport: sanitize/anonymize
// policy decisions (block_on handling, message building, plugin
// registration) are out of scope here and land with the plugin itself.
package googlemodelarmor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
)

const (
	// No local timeout default on purpose: MODEL_ARMOR_TIMEOUT in pkg/config
	// is the single owner of that value, the way openai_moderation does it.
	// A second literal here would be a second answer to the same question,
	// free to drift from the first.
	maxResponseBytes = 1 << 20

	hostTemplate = "https://modelarmor.%s.rep.googleapis.com"
	apiVersion   = "v1"

	actionSanitizeUserPrompt    = "sanitizeUserPrompt"
	actionSanitizeModelResponse = "sanitizeModelResponse"
)

// tokenSource returns a bearer token to authorize a Model Armor call. It is
// injectable so tests never need real GCP credentials.
type tokenSource func(ctx context.Context) (string, error)

// errModelArmor reports a non-2xx from Model Armor. It deliberately carries
// only the status: an error body can echo back SDP findings and de-identified
// text, and an error string ends up in logs. Surfacing the very data this
// guardrail exists to contain would defeat the point of running it.
type errModelArmor struct {
	action string
	status int
}

func (e *errModelArmor) Error() string {
	return fmt.Sprintf("model_armor: %s unexpected status %d", e.action, e.status)
}

type client struct {
	http        *http.Client
	baseURL     string
	timeout     time.Duration
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
	adc := gcpauth.NewApplicationDefaultCache()
	return newClientWithTokenSource(baseURL, timeout, func(ctx context.Context) (string, error) {
		return adc.Token(ctx, gcpauth.CloudPlatformScope)
	})
}

func newClientWithTokenSource(baseURL string, timeout time.Duration, ts tokenSource) *client {
	// Borrow the pool's tuned transport (dial timeout, per-host connection
	// limits) keyed to this plugin, so our connections stay isolated from the
	// rest of the gateway. The pooled *http.Client itself is shared under that
	// key, so rather than mutating it we wrap its transport in our own client:
	// CheckRedirect must stay ours, to stop the bearer token following a
	// redirect off-host, and writing that field on a shared client would be a
	// data race.
	pooled := providers.NewHTTPClientPool().Get(PluginName, timeout)
	return &client{
		http: &http.Client{
			Transport: pooled.Transport,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL:     strings.TrimRight(baseURL, "/"),
		timeout:     timeout,
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

// sdp walks the two levels of nesting to the SDP payload, returning nil when
// the filter did not run or reported nothing.
func (r *SanitizationResult) sdp() *SDPResult {
	if r == nil || r.FilterResults.SDP == nil {
		return nil
	}
	return r.FilterResults.SDP.SdpFilterResult
}

// FilterResults holds every filter outcome Model Armor can return for a
// sanitize call. json.Unmarshal drops unknown keys, so a template that only
// evaluates a subset of these filters simply leaves the rest nil.
type FilterResults struct {
	SDP            *SDPFilterResult            `json:"sdp,omitempty"`
	RAI            *RAIFilterResult            `json:"rai,omitempty"`
	PIAndJailbreak *PIAndJailbreakFilterResult `json:"pi_and_jailbreak,omitempty"`
	MaliciousURIs  *MaliciousURIsFilterResult  `json:"malicious_uris,omitempty"`
	CSAM           *CSAMFilterResult           `json:"csam,omitempty"`
	VirusScan      *VirusScanFilterResult      `json:"virus_scan,omitempty"`
}

// SDPFilterResult is the sensitive-data-protection filter outcome. Like every
// other entry in FilterResults it wraps its payload in a per-filter key, here
// sdpFilterResult: the wire shape is
// filterResults -> sdp -> sdpFilterResult -> {inspect,deidentify,redact}Result.
type SDPFilterResult struct {
	SdpFilterResult *SDPResult `json:"sdpFilterResult,omitempty"`
}

// SDPResult holds the three mutually exclusive outcomes Model Armor can
// return for the SDP filter. Which one arrives is decided by the template,
// not by us: a template configured with only an inspect template reports
// InspectResult, and only one that also names a de-identify template fills
// DeidentifyResult with rewritten text. Both count as a sensitive-data match
// for blocking; only the second gives us anything to reinject.
type SDPResult struct {
	InspectResult    *SDPInspectResult    `json:"inspectResult,omitempty"`
	DeidentifyResult *SDPDeidentifyResult `json:"deidentifyResult,omitempty"`
	RedactResult     *SDPRedactResult     `json:"redactResult,omitempty"`
}

// SDPInspectResult is what an inspect-only template returns: sensitive data
// was found and named, but no rewritten text was produced.
type SDPInspectResult struct {
	MatchState string   `json:"matchState"`
	InfoTypes  []string `json:"infoTypes,omitempty"`
}

// SDPRedactResult is the redaction outcome, modelled so the union decodes
// completely; the plugin does not act on it today.
type SDPRedactResult struct {
	MatchState string `json:"matchState"`
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

// RAIFilterResult is the responsible-AI (hate speech, harassment, dangerous
// content, sexually explicit content) filter outcome.
type RAIFilterResult struct {
	RaiFilterResult *RAIResult `json:"raiFilterResult,omitempty"`
}

// RAIResult reports the overall RAI match state plus a per-category
// breakdown (e.g. hate_speech, dangerous, harassment, sexually_explicit).
type RAIResult struct {
	MatchState           string                         `json:"matchState"`
	RaiFilterTypeResults map[string]RAIFilterTypeResult `json:"raiFilterTypeResults,omitempty"`
}

// RAIFilterTypeResult is one RAI category's match state and confidence.
type RAIFilterTypeResult struct {
	MatchState      string `json:"matchState"`
	ConfidenceLevel string `json:"confidenceLevel,omitempty"`
}

// MaliciousURIsFilterResult is the malicious-URI filter outcome.
type MaliciousURIsFilterResult struct {
	MaliciousURIFilterResult *MaliciousURIResult `json:"maliciousUriFilterResult,omitempty"`
}

// MaliciousURIResult reports the match state and the URIs Model Armor flagged.
type MaliciousURIResult struct {
	MatchState   string                    `json:"matchState"`
	MatchedItems []MaliciousURIMatchedItem `json:"maliciousUriMatchedItems,omitempty"`
}

// MaliciousURIMatchedItem is one URI Model Armor flagged as malicious.
type MaliciousURIMatchedItem struct {
	URI string `json:"uri"`
}

// CSAMFilterResult is the CSAM (child sexual abuse material) filter outcome.
type CSAMFilterResult struct {
	CSAMFilterFilterResult *CSAMResult `json:"csamFilterFilterResult,omitempty"`
}

// CSAMResult reports the CSAM filter's match state.
type CSAMResult struct {
	MatchState string `json:"matchState"`
}

// VirusScanFilterResult is the malware/virus scan outcome, the sixth member
// of the FilterResult union. It only fires for the document scanning paths
// this plugin does not implement, and block_on has no entry for it, so
// nothing acts on it; it is modelled so the union decodes completely rather
// than silently dropping a filter a template may well have enabled.
type VirusScanFilterResult struct {
	VirusScanFilterResult *VirusScanResult `json:"virusScanFilterResult,omitempty"`
}

// VirusScanResult reports the virus scan's match state.
type VirusScanResult struct {
	MatchState string `json:"matchState"`
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
	// Bound the whole call, not just the HTTP round trip. The token is acquired
	// before http.Do, so an http.Client.Timeout alone would leave credential
	// resolution unbounded on the request path.
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

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
	// DrainBody rather than a bare Close: with the LimitReader below, an
	// oversized response would otherwise leave unread bytes on the wire and
	// hand a dirty connection back to the pool.
	defer providers.DrainBody(res.Body)

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("model_armor: read response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, &errModelArmor{action: action, status: res.StatusCode}
	}
	// Say "too large" rather than letting a truncated payload surface as a
	// decode failure and send whoever debugs it hunting for malformed JSON.
	if len(raw) >= maxResponseBytes {
		return nil, fmt.Errorf("model_armor: %s response exceeds %d bytes", action, maxResponseBytes)
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
