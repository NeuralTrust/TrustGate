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

package request

// SetAgentAccess sets one principal's agent access. An empty mode deletes the
// row.
type SetAgentAccess struct {
	PrincipalType string   `json:"principal_type"`
	PrincipalID   string   `json:"principal_id"`
	Mode          string   `json:"mode"`
	RegistryIDs   []string `json:"registry_ids"`
}
