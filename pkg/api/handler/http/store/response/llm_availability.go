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

package response

// LLMAvailability says whether the gateway's data planes serve the LLM Store.
type LLMAvailability struct {
	Available bool `json:"available"`
	// Reason is available, no_data_plane, version_unknown or data_plane_outdated.
	Reason     string `json:"reason"`
	MinVersion string `json:"min_version"`
	// LowestVersion is the oldest data-plane version seen, set only when outdated.
	LowestVersion string `json:"lowest_version,omitempty"`
}
