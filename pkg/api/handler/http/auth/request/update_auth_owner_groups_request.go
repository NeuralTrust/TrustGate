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

// UpdateAuthOwnerGroupsRequest is the directory groups of a personal key's
// owner, and optionally their email. An empty list clears the groups; an
// empty email clears it, and no email leaves it as it is.
type UpdateAuthOwnerGroupsRequest struct {
	Groups []string `json:"groups" example:"engineering,sre"`
	Email  *string  `json:"email,omitempty" example:"alice@example.com"`
}
