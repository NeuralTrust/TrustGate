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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	evaluatePath           = "/v1/evaluate"
	traceIDHeader          = "X-Trace-ID"
	playgroundOriginHeader = "X-AG-Playground"
	maxResponseBytes       = 1 << 20

	// maxBufferedPayloadBytes is the largest evaluate payload a buffered leg
	// sends. A normal prompt or completion is a few tens of KiB and an agent
	// conversation with its tool results a few hundred; TrustGuard itself only
	// refuses a body above 10 MiB, long after a padded one has run the call into
	// its timeout, which fails open. The bound is half of maxResponseBytes on
	// purpose: the mask answers with the payload echoed back, so a payload at
	// the bound still fits an answer that has to carry it once more. Above it
	// the request is the input's doing and is refused locally as
	// payload_too_large; a streamed leg sends a 64 KiB window and never gets here.
	maxBufferedPayloadBytes = 512 << 10

	// evaluateTimeoutHeader tells TrustGuard how long, in milliseconds, this
	// call will wait. TrustGuard holds its detectors to a little less, so one
	// that runs out of time fails open inside the answer instead of outliving
	// the call and turning into a gateway timeout (ENG-1671).
	evaluateTimeoutHeader = "X-Evaluate-Timeout-Ms"

	// peerService must match TrustGuard's own service.name, and evaluateSpanName
	// stays a bounded label rather than the request target.
	peerService      = "trustguard"
	evaluateSpanName = "trustguard.evaluate"
)

var errUnauthorized = errors.New("trustguard: unauthorized")

// rateLimitHeaderNames are forwarded from TrustGuard evaluate 429 to the gateway client.
var rateLimitHeaderNames = []string{
	"Retry-After",
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reason",
}

// payloadTooLargeError is TrustGuard refusing the body for its size (HTTP 413).
// It is a verdict on the request's own content, so unlike a transport failure
// it is classified as input.
type payloadTooLargeError struct{}

func (e *payloadTooLargeError) Error() string {
	return "trustguard: payload too large"
}

// attachmentRejectedError is TrustGuard answering 400 "invalid attachment": the
// resolver could not fetch or decode an attachment this request carried. Like a
// 413 it is a verdict on the request's own content, so it is classified as
// input. A 400 with any other body says the call itself was malformed, which no
// client input can cause and is not this error.
type attachmentRejectedError struct{}

func (e *attachmentRejectedError) Error() string {
	return "trustguard: invalid attachment"
}

type rateLimitedError struct {
	headers map[string][]string
	body    []byte
}

func (e *rateLimitedError) Error() string {
	return "trustguard: rate limit exceeded"
}

// entitlementsUnavailableError is returned when TrustGuard evaluate cannot
// resolve plan entitlements (HTTP 503). Must not fail-open.
type entitlementsUnavailableError struct {
	body []byte
}

func (e *entitlementsUnavailableError) Error() string {
	return "trustguard: rate limit entitlements unavailable"
}

// authRejectedError is returned when TrustGuard deliberately refuses the
// evaluate call (403, or 401 after token refresh) or the token call (400, 401,
// 403). Must not fail-open: the guard is reachable and the plugin is
// misconfigured or unauthorized. code is the OAuth error code the token
// endpoint named, for the operator's log only; it never reaches the caller.
type authRejectedError struct {
	status int
	code   string
}

func (e *authRejectedError) Error() string {
	if e == nil {
		return "trustguard: unauthorized"
	}
	if e.code != "" {
		return fmt.Sprintf("trustguard: unauthorized status %d (%s)", e.status, e.code)
	}
	return fmt.Sprintf("trustguard: unauthorized status %d", e.status)
}

type client struct {
	http *http.Client
}

type clientConfig struct {
	baseTransport http.RoundTripper
}

type clientOption func(*clientConfig)

func withBaseTransport(base http.RoundTripper) clientOption {
	return func(cfg *clientConfig) { cfg.baseTransport = base }
}

// newClient builds the evaluate client. Its Timeout is only a backstop:
// every call brings its own deadline, the deployment-wide timeout or the stream
// guard timeout, and a shorter client timeout would cap it without saying so.
// The backstop never sits below either.
func newClient(timeout time.Duration, opts ...clientOption) *client {
	cfg := clientConfig{baseTransport: http.DefaultTransport}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &client{http: &http.Client{
		Timeout:   max(defaultStreamingGuardTimeout, timeout),
		Transport: o11y.InternalTransportOver(cfg.baseTransport, peerService, evaluateSpanName),
	}}
}

func (c *client) Guard(ctx context.Context, baseURL, token, traceID string, body GuardRequest, playground bool) (*GuardResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("trustguard: marshal request: %w", err)
	}
	endpoint := strings.TrimRight(baseURL, "/") + evaluatePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("trustguard: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentTypeJSON)
	if traceID != "" {
		req.Header.Set(traceIDHeader, traceID)
	}
	if playground {
		req.Header.Set(playgroundOriginHeader, "1")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if ms := time.Until(deadline).Milliseconds(); ms > 0 {
			req.Header.Set(evaluateTimeoutHeader, strconv.FormatInt(ms, 10))
		}
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trustguard: guard call: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("trustguard: read response: %w", err)
	}
	if res.StatusCode == http.StatusUnauthorized {
		return nil, errUnauthorized
	}
	if res.StatusCode == http.StatusForbidden {
		return nil, &authRejectedError{status: http.StatusForbidden}
	}
	if res.StatusCode == http.StatusTooManyRequests {
		return nil, &rateLimitedError{
			headers: copyRateLimitHeaders(res.Header),
			body:    append([]byte(nil), raw...),
		}
	}
	if res.StatusCode == http.StatusRequestEntityTooLarge {
		return nil, &payloadTooLargeError{}
	}
	if res.StatusCode == http.StatusBadRequest && isInvalidAttachment(raw) {
		return nil, &attachmentRejectedError{}
	}
	if res.StatusCode == http.StatusServiceUnavailable {
		return nil, &entitlementsUnavailableError{body: append([]byte(nil), raw...)}
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("trustguard: unexpected status %d", res.StatusCode)
	}
	if len(raw) >= maxResponseBytes {
		return nil, &pluginutil.AnswerTooLargeError{Provider: "trustguard", Limit: maxResponseBytes}
	}
	var out GuardResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("trustguard: decode response: %w", err)
	}
	return &out, nil
}

const invalidAttachmentMessage = "invalid attachment"

func isInvalidAttachment(body []byte) bool {
	var envelope struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(body, &envelope) == nil && envelope.Error == invalidAttachmentMessage
}

func copyRateLimitHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(rateLimitHeaderNames))
	for _, name := range rateLimitHeaderNames {
		values := h.Values(name)
		if len(values) == 0 {
			continue
		}
		out[name] = append([]string(nil), values...)
	}
	return out
}
