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

type providerErrorEnvelope struct {
	Error *providerErrorBody `json:"error"`
}

type providerErrorBody struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Status  string `json:"status"`
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
