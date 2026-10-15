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

package plugins

import (
	"errors"
	"net/http"
	"net/textproto"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// DefaultBlockMessage is the vendor-neutral message a guardrail plugin returns
// to the caller when its configured message is empty or whitespace-only. Every
// guardrail plugin (azure_content_safety, bedrock_guardrail, google_model_armor,
// openai_moderation) falls back to this same string on both the buffered and
// streamed legs, so the caller never sees which vendor made the call.
const DefaultBlockMessage = "This content violates our usage policy."

// PluginError is returned by a plugin to reject a request and short-circuit the
// chain with a specific HTTP status (e.g. rate limit 429, request too large 413).
type PluginError struct {
	StatusCode int
	Type       string
	Message    string
	Headers    map[string][]string
	Body       []byte

	// NotAVerdict marks a 403 that is not a policy stopping a leg of the
	// exchange: a configuration or guard failure that happens to answer 403.
	// WithBlockDirection leaves it without the direction header. It is an
	// explicit field rather than a match on Type because some of these errors
	// carry no Type, and a Type list would have to be kept in step by hand.
	NotAVerdict bool
}

func (e *PluginError) Error() string {
	return e.Message
}

// AsPluginError reports whether err is (or wraps) a *PluginError and returns it.
func AsPluginError(err error) (*PluginError, bool) {
	var pe *PluginError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

// UndecodableRequestError rejects a request whose body does not decode in its
// wire format. A plugin that enforces a policy on the tools of a request
// returns it rather than let a body it could not inspect reach the upstream,
// which may accept what the gateway could not decode.
func UndecodableRequestError(plugin string) *PluginError {
	return &PluginError{
		StatusCode: http.StatusBadRequest,
		Type:       "invalid_request_body",
		Message:    plugin + ": the request body could not be decoded",
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
	}
}

const (
	// BlockDirectionHeader tells the caller which leg of the exchange a policy
	// block ended: the request it sent or the response the model produced. It
	// follows the X-NeuralTrust-* naming of the gateway's other response headers.
	BlockDirectionHeader = "X-NeuralTrust-Block-Direction"

	// BlockDirectionInput is a block at pre_request (or post_request).
	BlockDirectionInput = "input"
	// BlockDirectionOutput is a block at pre_response or post_response, and a
	// stream cut.
	BlockDirectionOutput = "output"
)

// BlockDirectionForStage names the leg a stage inspects.
func BlockDirectionForStage(stage policy.Stage) string {
	if stage == policy.StagePreResponse || stage == policy.StagePostResponse {
		return BlockDirectionOutput
	}
	return BlockDirectionInput
}

// WithBlockDirection returns pe with BlockDirectionHeader set to direction when
// pe is a policy block, and pe untouched otherwise.
//
// A policy block is a 403 by which a policy stopped the request or response
// leg; guard failures and configuration failures do not carry it. Every plugin
// that denies on its own judgement answers 403 (the guardrails, the allowlists,
// the cost cap), while failures that are not a verdict on the content use
// another status: 429 for a rate limit, 400 for an undecodable body, 502/503/504
// for a guard that could not be consulted. The few failures that answer 403
// anyway set NotAVerdict. A plugin that already set the header keeps its own
// value. The receiver is never mutated: plugins may return shared errors.
func WithBlockDirection(pe *PluginError, direction string) *PluginError {
	if pe == nil || pe.StatusCode != http.StatusForbidden || pe.NotAVerdict || direction == "" {
		return pe
	}
	want := textproto.CanonicalMIMEHeaderKey(BlockDirectionHeader)
	headers := make(map[string][]string, len(pe.Headers)+1)
	for k, v := range pe.Headers {
		if textproto.CanonicalMIMEHeaderKey(k) == want {
			return pe
		}
		headers[k] = v
	}
	headers[BlockDirectionHeader] = []string{direction}
	out := *pe
	out.Headers = headers
	return &out
}

// stampedError keeps the chain a plugin wrapped its *PluginError in while
// making errors.As hand out the stamped copy instead of the original, so a
// caller's AsPluginError sees the header and errors.Is/As on the rest of the
// chain still match.
type stampedError struct {
	err     error
	stamped *PluginError
}

func (e *stampedError) Error() string { return e.err.Error() }
func (e *stampedError) Unwrap() error { return e.err }

func (e *stampedError) As(target any) bool {
	if t, ok := target.(**PluginError); ok {
		*t = e.stamped
		return true
	}
	return false
}

// stampBlockDirection returns err itself unless it is, or wraps, a 403
// *PluginError that WithBlockDirection actually changed.
func stampBlockDirection(err error, direction string) error {
	pe, ok := AsPluginError(err)
	if !ok {
		return err
	}
	stamped := WithBlockDirection(pe, direction)
	if stamped == pe {
		return err
	}
	if err == error(pe) {
		return stamped
	}
	return &stampedError{err: err, stamped: stamped}
}
