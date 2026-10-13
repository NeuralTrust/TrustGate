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

package openaimoderation

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
	moderationsPath  = "/v1/moderations"
	maxResponseBytes = 1 << 20
)

type errModeration struct {
	status     int
	retryAfter time.Duration
	// configShaped is set from the error envelope when a 400 is about the
	// policy's model or key and not about the input, or a 429 is the account's
	// quota and not a rate.
	configShaped bool
}

var _ pluginutil.Rejection = (*errModeration)(nil)

func (e *errModeration) Rejection() (int, bool) { return e.status, e.configShaped }

// RetryAfter is the wait the answer asked for, zero when it asked for none.
func (e *errModeration) RetryAfter() time.Duration { return e.retryAfter }

func (e *errModeration) Error() string {
	return fmt.Sprintf("openai_moderation: unexpected status %d", e.status)
}

type client struct {
	http    *http.Client
	timeout time.Duration
}

func newClient(timeout time.Duration) *client {
	return &client{
		http:    providers.NewTrustedHTTPClientPool().Get(PluginName, timeout),
		timeout: timeout,
	}
}

func (c *client) Moderate(ctx context.Context, baseURL, apiKey string, body moderationRequest) (*moderationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("openai_moderation: marshal request: %w", err)
	}

	endpoint := strings.TrimRight(baseURL, "/") + moderationsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("openai_moderation: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai_moderation: moderations call: %w", err)
	}
	defer providers.DrainBody(res.Body)

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("openai_moderation: read response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, &errModeration{
			status: res.StatusCode, configShaped: rejectsConfiguration(res.StatusCode, raw),
			retryAfter: pluginutil.ParseRetryAfter(res.Header.Get("Retry-After"), time.Now()),
		}
	}

	var out moderationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("openai_moderation: decode response: %w", err)
	}
	return &out, nil
}

type errorEnvelope struct {
	Error struct {
		Param string `json:"param"`
		Code  string `json:"code"`
	} `json:"error"`
}

// configurationCodes are the error codes of a 400 that is about the policy's
// model or key and not about the input.
var configurationCodes = map[string]struct{}{
	"model_not_found": {}, "invalid_api_key": {}, "invalid_model": {},
}

// quotaCodes are the error codes of a 429 that is the account's own quota, not
// a rate: no credit left, or the billing limit reached. They are documented as
// code values of the error object in OpenAI's error-codes guide, and waiting
// does not clear them, unlike rate_limit_exceeded.
var quotaCodes = map[string]struct{}{
	"insufficient_quota": {}, "billing_hard_limit_reached": {},
}

// rejectsConfiguration reports whether an error in OpenAI's envelope is about
// the policy and not about the input: a 400 that names the model or whose code
// says the model or key is unusable, or a 429 whose code says the account's
// quota is spent. Anything else, an input param above all and any shape this
// does not recognise, is read as the content's (a 400) or a rate (a 429), so an
// unknown error cannot be used to skip the guardrail.
func rejectsConfiguration(status int, body []byte) bool {
	if status != http.StatusBadRequest && status != http.StatusTooManyRequests {
		return false
	}
	var env errorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	if status == http.StatusTooManyRequests {
		_, ok := quotaCodes[env.Error.Code]
		return ok
	}
	if env.Error.Param == "model" {
		return true
	}
	_, ok := configurationCodes[env.Error.Code]
	return ok
}
