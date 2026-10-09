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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	defaultTimeout   = 10 * time.Second
	maxResponseBytes = 1 << 20
)

type client struct {
	http *http.Client
}

func newClient() *client {
	// endpoint is a policy setting a tenant controls, so the transport comes
	// from the guarded provider pool: it refuses private, loopback and
	// link-local destinations at dial time, redirects included. Only the
	// transport is borrowed: the client needs its own CheckRedirect, which the
	// pool's client does not set.
	pooled := providers.NewHTTPClientPool().Get(PluginName, defaultTimeout)
	return &client{http: &http.Client{
		Transport: pooled.Transport,
		Timeout:   defaultTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

type analyzeRequest struct {
	Text       string   `json:"text"`
	Categories []string `json:"categories,omitempty"`
	OutputType string   `json:"outputType"`
}

type categoryAnalysis struct {
	Category string `json:"category"`
	Severity int    `json:"severity"`
}

type analyzeResponse struct {
	CategoriesAnalysis []categoryAnalysis `json:"categoriesAnalysis"`
}

// statusError is a non-2xx answer from Azure. It carries only the status: the
// body can echo the text that was analysed, and an error string ends up in logs.
type statusError struct {
	status     int
	retryAfter time.Duration
	// configShaped is set from the error envelope when a 400 is about the
	// call's configuration (api-version, categories, output type) and not about
	// the text, or a 429 says the resource's call volume quota is spent.
	configShaped bool
}

var _ pluginutil.Rejection = (*statusError)(nil)

func (e *statusError) Rejection() (int, bool) { return e.status, e.configShaped }

// RetryAfter is the wait the answer asked for, zero when it asked for none.
func (e *statusError) RetryAfter() time.Duration { return e.retryAfter }

func (e *statusError) Error() string {
	return fmt.Sprintf("azure_content_safety: unexpected status %d", e.status)
}

func (c *client) Analyze(ctx context.Context, endpoint, apiKey string, body analyzeRequest) (*analyzeResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("azure_content_safety: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("azure_content_safety: build request: %w", err)
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure_content_safety: analyze call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("azure_content_safety: read response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, &statusError{
			status: res.StatusCode, configShaped: rejectsConfiguration(res.StatusCode, raw),
			retryAfter: pluginutil.ParseRetryAfter(res.Header.Get("Retry-After"), time.Now()),
		}
	}
	var out analyzeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("azure_content_safety: decode response: %w", err)
	}
	return &out, nil
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Target  string `json:"target"`
	} `json:"error"`
}

// configurationTargets are the request members that come from the policy and
// not from the text: the api-version of the endpoint and the categories and
// output type the plugin requests.
var configurationTargets = map[string]struct{}{
	"api-version": {}, "apiversion": {}, "categories": {}, "outputtype": {},
}

// rejectsConfiguration reports whether a 400 in Azure's error envelope names
// the call's configuration: a target that is not the text, or an api-version
// code. Anything else, including a shape this does not recognise, is read as
// the content's, so an unknown error cannot be used to skip the guardrail.
func rejectsConfiguration(status int, body []byte) bool {
	if status == http.StatusTooManyRequests {
		return spentCallVolumeQuota(body)
	}
	if status != http.StatusBadRequest {
		return false
	}
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	if _, ok := configurationTargets[strings.ToLower(env.Error.Target)]; ok {
		return true
	}
	code := strings.ToLower(env.Error.Code)
	return strings.Contains(code, "apiversion") || strings.Contains(code, "api-version")
}

// spentCallVolumeQuota reports whether a 429 says the resource ran out of its
// call volume quota ("Out of call volume quota for ... pricing tier. Please
// retry after N days"), which Azure answers for a free tier that is spent. It is
// the subscription's tier, not a rate, and waiting a second does not clear it.
// A rate limit ("exceeded call rate limit") is a throttle.
func spentCallVolumeQuota(body []byte) bool {
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(env.Error.Message), "out of call volume quota")
}
