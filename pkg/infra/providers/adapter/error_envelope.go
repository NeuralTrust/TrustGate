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

func StreamErrorEvent(source Format, message string) []byte {
	if message == "" {
		message = "upstream stream terminated unexpectedly"
	}
	switch normalizeFormat(source) {
	case FormatAnthropic:
		data, _ := json.Marshal(anthropicErrorEnvelope{
			Type: "error",
			Error: anthropicErrorBody{
				Type:    "api_error",
				Message: message,
			},
		})
		event := append([]byte("event: error\ndata: "), data...)
		return append(event, '\n')
	case FormatGemini:
		data := EncodeErrorBody(FormatGemini, http.StatusInternalServerError, message)
		event := append([]byte("data: "), data...)
		return append(event, '\n')
	default:
		return []byte(`data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}`)
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
