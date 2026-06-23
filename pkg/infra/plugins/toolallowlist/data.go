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

package toolallowlist

const (
	actionFiltered    = "filtered"
	actionNoTools     = "no_tools"
	actionRejected    = "rejected"
	actionStripped    = "stripped"
	actionPassThrough = "pass_through"
	actionSkipped     = "skipped"
)

type ToolAllowlistData struct {
	Provider       string   `json:"provider"`
	ToolsRequested []string `json:"tools_requested"`
	ToolsAllowed   []string `json:"tools_allowed"`
	ToolsRemoved   []string `json:"tools_removed"`
	Action         string   `json:"action"`
	OnEmpty        string   `json:"on_empty,omitempty"`
	Decision       string   `json:"decision"`
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Type               string   `json:"type"`
	Requested          []string `json:"requested"`
	AllowedAfterFilter []string `json:"allowed_after_filter"`
}

func newErrorBody(requested []string) errorBody {
	return errorBody{Error: errorDetail{
		Type:               "no_tools_allowed",
		Requested:          requested,
		AllowedAfterFilter: []string{},
	}}
}
