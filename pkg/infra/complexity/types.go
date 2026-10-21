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

package complexity

type scoreRequest struct {
	Input    string `json:"input"`
	TenantID string `json:"tenant_id,omitempty"`
}

type scoreResponse struct {
	Revision string   `json:"revision"`
	Score    float64  `json:"score"`
	RawScore *float64 `json:"raw_score"`
}

// inputLimits are the per-request input limits the firewall publishes on
// /v1/complexity/config. A nil limit means unbounded.
type inputLimits struct {
	MaxInputChars *int `json:"max_input_chars"`
	MaxTextChars  *int `json:"max_text_chars"`
}

// effective returns the strictest limit in characters, or 0 when unbounded.
func (l inputLimits) effective() int {
	limit := 0
	for _, v := range []*int{l.MaxInputChars, l.MaxTextChars} {
		if v != nil && *v > 0 && (limit == 0 || *v < limit) {
			limit = *v
		}
	}
	return limit
}
