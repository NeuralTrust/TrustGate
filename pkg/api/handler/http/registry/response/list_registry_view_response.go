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

type ListRegistryViewResponse struct {
	Items          []RegistryResponse              `json:"items,omitempty"`
	Page           int                             `json:"page,omitempty"`
	Size           int                             `json:"size,omitempty"`
	Total          int                             `json:"total,omitempty"`
	View           string                          `json:"view,omitempty"`
	Groups         []RegistryProviderGroupResponse `json:"groups,omitempty"`
	TotalGroups    int                             `json:"total_groups,omitempty"`
	TotalInstances int                             `json:"total_instances,omitempty"`
}
