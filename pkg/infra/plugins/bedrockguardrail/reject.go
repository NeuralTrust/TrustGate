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

package bedrockguardrail

import (
	"encoding/json"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const typeGuardrailBlocked = "guardrail_blocked"

func blockError(f finding) *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       typeGuardrailBlocked,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       blockBody(f),
	}
}

func blockBody(f finding) []byte {
	body := struct {
		Error struct {
			Type   string `json:"type"`
			Policy string `json:"policy"`
			Name   string `json:"name,omitempty"`
		} `json:"error"`
	}{}
	body.Error.Type = typeGuardrailBlocked
	body.Error.Policy = f.policy
	body.Error.Name = f.name
	raw, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"error":{"type":"guardrail_blocked"}}`)
	}
	return raw
}
