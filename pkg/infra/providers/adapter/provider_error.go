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
	"strings"
)

var retryableErrorMarkers = []string{
	"overloaded",
	"rate_limit",
	"rate limit",
	"insufficient_quota",
	"service_unavailable",
	"server_error",
	"server_overloaded",
	"try again",
	"temporarily unavailable",
}

var modelMissingMarkers = []string{
	"model_not_found",
	"not_found",
	"not found",
	"does not exist",
	"unknown model",
	"unsupported model",
	"invalid model",
	"identifier is invalid",
	"does not have access",
	"no access",
}

type modelErrorEnvelope struct {
	Error   *modelErrorBody `json:"error"`
	Type    string          `json:"__type"`
	Message string          `json:"message"`
}

type modelErrorBody struct {
	Type    string          `json:"type"`
	Code    json.RawMessage `json:"code"`
	Status  string          `json:"status"`
	Message string          `json:"message"`
}

func BodyCarriesModelNotFound(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var env modelErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	parts := []string{env.Type, env.Message}
	if env.Error != nil {
		parts = append(parts, env.Error.Type, string(env.Error.Code), env.Error.Status, env.Error.Message)
	}
	haystack := strings.ToLower(strings.Join(parts, " "))
	if !strings.Contains(haystack, "model") {
		return false
	}
	for _, marker := range modelMissingMarkers {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}

func ProviderErrorMessage(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var env modelErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ""
	}
	if env.Error != nil && env.Error.Message != "" {
		return env.Error.Message
	}
	return env.Message
}

type providerErrorEnvelope struct {
	Error *providerErrorBody `json:"error"`
}

type providerErrorBody struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Status  string `json:"status"`
	Param   string `json:"param"`
	Message string `json:"message"`
}

func BodyCarriesRetryableError(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var env providerErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil || env.Error == nil {
		return false
	}
	haystack := strings.ToLower(strings.Join([]string{
		env.Error.Type,
		env.Error.Code,
		env.Error.Status,
		env.Error.Message,
	}, " "))
	for _, marker := range retryableErrorMarkers {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}

// BodyRequiresReasoningEffortNone reports whether OpenAI rejected function
// tools because the model's default reasoning effort is incompatible with the
// Chat Completions surface.
func BodyRequiresReasoningEffortNone(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var env providerErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil || env.Error == nil {
		return false
	}
	if env.Error.Type != "" && !strings.EqualFold(env.Error.Type, "invalid_request_error") {
		return false
	}
	if env.Error.Param != "" && !strings.EqualFold(env.Error.Param, "reasoning_effort") {
		return false
	}
	message := strings.ToLower(env.Error.Message)
	return strings.Contains(message, "function tools") &&
		strings.Contains(message, "reasoning_effort") &&
		strings.Contains(message, "not supported") &&
		(strings.Contains(message, "set reasoning_effort to 'none'") ||
			strings.Contains(message, `set reasoning_effort to "none"`) ||
			strings.Contains(message, "set reasoning_effort to none"))
}
