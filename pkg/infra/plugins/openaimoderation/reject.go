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
	"encoding/json"
	"net/http"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const (
	typeContentFlagged = "content_flagged"
	typeUnavailable    = "moderation_unavailable"

	defaultBlockMessage = "request blocked by content policy"
	unavailableMessage  = "content moderation is temporarily unavailable"
)

const unavailableBodyJSON = `{"error":{"type":"moderation_unavailable","message":"content moderation is temporarily unavailable"}}`

func blockBody(violations []violation) []byte {
	body := struct {
		Error struct {
			Type       string      `json:"type"`
			Categories []violation `json:"categories"`
		} `json:"error"`
	}{}
	body.Error.Type = typeContentFlagged
	body.Error.Categories = violations

	raw, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"error":{"type":"content_flagged"}}`)
	}
	return raw
}

func blockError(message string, violations []violation) *appplugins.PluginError {
	msg := strings.TrimSpace(message)
	if msg == "" {
		msg = defaultBlockMessage
	}
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       typeContentFlagged,
		Message:    msg,
		Body:       blockBody(violations),
	}
}

func unavailableError() *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: http.StatusBadGateway,
		Type:       typeUnavailable,
		Message:    unavailableMessage,
		Body:       []byte(unavailableBodyJSON),
	}
}
