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
	"encoding/json"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const (
	typeContentFlagged  = "content_flagged"
	defaultBlockMessage = "request blocked by Azure Content Safety"
)

type breachedCategory struct {
	Category  string `json:"category"`
	Severity  int    `json:"severity"`
	Threshold int    `json:"threshold"`
}

func blockError(message string, breaches []breachedCategory) *appplugins.PluginError {
	if message == "" {
		message = defaultBlockMessage
	}
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       typeContentFlagged,
		Message:    message,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       blockBody(message, breaches),
	}
}

func blockBody(message string, breaches []breachedCategory) []byte {
	body := struct {
		Error struct {
			Type       string             `json:"type"`
			Message    string             `json:"message"`
			Categories []breachedCategory `json:"categories,omitempty"`
		} `json:"error"`
	}{}
	body.Error.Type = typeContentFlagged
	body.Error.Message = message
	body.Error.Categories = breaches
	raw, err := json.Marshal(body)
	if err != nil {
		return []byte(message)
	}
	return raw
}
