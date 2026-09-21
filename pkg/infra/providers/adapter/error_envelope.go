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

package adapter

import (
	"encoding/json"
	"net/http"
)

type anthropicErrorEnvelope struct {
	Type  string             `json:"type"`
	Error anthropicErrorBody `json:"error"`
}

type anthropicErrorBody struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type geminiErrorEnvelope struct {
	Error geminiErrorBody `json:"error"`
}

type geminiErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

type cohereErrorEnvelope struct {
	Message string `json:"message"`
}

type openaiStreamErrorEnvelope struct {
	Error openaiStreamErrorBody `json:"error"`
}

type openaiStreamErrorBody struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

type responsesStreamErrorEvent struct {
	Type    string  `json:"type"`
	Code    string  `json:"code"`
	Message string  `json:"message"`
	Param   *string `json:"param"`
}

const (
	// StreamErrorTypeUpstream and StreamErrorMessageUpstreamTerminated are the
	// wire values the proxy has always emitted when an upstream stream dies
	// mid-flight; they are exported so the call site keeps dialect strings out
	// of the HTTP handler.
	StreamErrorTypeUpstream              = "upstream_error"
	StreamErrorMessageUpstreamTerminated = "upstream stream terminated unexpectedly"
)

const (
	defaultStreamBlockedReason  = "content_filter"
	defaultStreamBlockedMessage = "response blocked by content filter"
)

// streamBlockedReason keeps caller-supplied reasons out of the dialect fields
// that clients surface to end users. A plugin name, detector id or TrustGuard
// category would otherwise land verbatim in OpenAI's error.type.
func streamBlockedReason(reason string) string {
	switch reason {
	case defaultStreamBlockedReason:
		return reason
	default:
		return defaultStreamBlockedReason
	}
}

// AdaptErrorBody rewrites an upstream error body into the ingress client's
// dialect when the two formats differ. OpenAI-family bodies are returned intact.
func AdaptErrorBody(body []byte, status int, source Format) []byte {
	if !NeedsAdaptedError(source) {
		return body
	}
	msg := ProviderErrorMessage(body)
	if msg == "" {
		msg = http.StatusText(status)
	}
	return EncodeErrorBody(source, status, msg)
}

// EncodeErrorBody encodes a gateway-originated error in the client's dialect.
func EncodeErrorBody(source Format, status int, message string) []byte {
	if message == "" {
		message = http.StatusText(status)
	}
	switch normalizeFormat(source) {
	case FormatAnthropic:
		out, _ := json.Marshal(anthropicErrorEnvelope{
			Type: "error",
			Error: anthropicErrorBody{
				Type:    anthropicErrorType(status),
				Message: message,
			},
		})
		return out
	case FormatGemini:
		out, _ := json.Marshal(geminiErrorEnvelope{
			Error: geminiErrorBody{
				Code:    status,
				Message: message,
				Status:  geminiRPCStatus(status),
			},
		})
		return out
	case FormatCohere:
		out, _ := json.Marshal(cohereErrorEnvelope{Message: message})
		return out
	default:
		out, _ := json.Marshal(map[string]any{
			"error": map[string]string{
				"type":    "invalid_request_error",
				"message": message,
			},
		})
		return out
	}
}

// StreamErrorEvent encodes a mid-stream error as SSE in the client's dialect.
// status drives the Anthropic and Gemini error taxonomies; errType is the
// OpenAI-family error type, which the other dialects have no slot for.
func StreamErrorEvent(source Format, status int, errType, message string) []byte {
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if errType == "" {
		errType = StreamErrorTypeUpstream
	}
	if message == "" {
		message = StreamErrorMessageUpstreamTerminated
	}
	switch normalizeFormat(source) {
	case FormatAnthropic:
		event := append([]byte("event: error\ndata: "), EncodeErrorBody(FormatAnthropic, status, message)...)
		return append(event, '\n')
	case FormatGemini:
		event := append([]byte("data: "), EncodeErrorBody(FormatGemini, status, message)...)
		return append(event, '\n')
	default:
		data, _ := json.Marshal(openaiStreamErrorEnvelope{
			Error: openaiStreamErrorBody{
				Message: message,
				Type:    errType,
			},
		})
		return append([]byte("data: "), data...)
	}
}

// StreamBlockedEvent encodes the error-envelope channel for a guardrail block
// on an in-flight stream. It is the secondary signal: the primary one is the
// finish-reason terminator each dialect carries on its own stream chunks,
// synthesised through EncodeStreamChunkFor. A blocked stream emits the
// finish-reason terminator first and this event after it, never this event
// alone — emitting it alone leaves an Anthropic content block or a Responses
// output_item unterminated, which is the failure the terminators exist to
// avoid.
//
// Cohere has no error member in its streamed-response union, so it falls
// through to the default rather than emit a discriminant its SDK skips
// silently; its block travels as ERROR on the message-end terminator.
//
// Each element is one SSE line and every dialect ends with the same empty-line
// separator, so callers frame them identically. reason reaches the wire only
// where the dialect has a free-form slot (OpenAI-chat "type", Responses
// "code") and is constrained to the closed set streamBlockedReason allows; the
// rest carry the block through their own permission-denied taxonomy.
func StreamBlockedEvent(source Format, reason, message string) [][]byte {
	reason = streamBlockedReason(reason)
	if message == "" {
		message = defaultStreamBlockedMessage
	}
	switch normalizeFormat(source) {
	case FormatAnthropic:
		return SSEEvent("error", EncodeErrorBody(FormatAnthropic, http.StatusForbidden, message))
	case FormatGemini:
		return SSEData(EncodeErrorBody(FormatGemini, http.StatusForbidden, message))
	case FormatOpenAIResponses:
		data, _ := json.Marshal(responsesStreamErrorEvent{
			Type:    "error",
			Code:    reason,
			Message: message,
		})
		return SSEEvent("error", data)
	default:
		data, _ := json.Marshal(openaiStreamErrorEnvelope{
			Error: openaiStreamErrorBody{
				Message: message,
				Type:    reason,
			},
		})
		return SSEData(data)
	}
}

func NeedsAdaptedError(source Format) bool {
	switch normalizeFormat(source) {
	case FormatAnthropic, FormatGemini, FormatCohere:
		return true
	default:
		return false
	}
}

func anthropicErrorType(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusServiceUnavailable, 529:
		return "overloaded_error"
	default:
		return "api_error"
	}
}

func geminiRPCStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "INVALID_ARGUMENT"
	case http.StatusUnauthorized:
		return "UNAUTHENTICATED"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusTooManyRequests:
		return "RESOURCE_EXHAUSTED"
	case http.StatusInternalServerError:
		return "INTERNAL"
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return "UNAVAILABLE"
	case http.StatusGatewayTimeout:
		return "DEADLINE_EXCEEDED"
	default:
		return "UNKNOWN"
	}
}
