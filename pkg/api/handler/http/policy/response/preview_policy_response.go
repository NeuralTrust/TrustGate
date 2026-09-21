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

import "encoding/json"

// PreviewPolicyResponse reports what the plugin did to the sample request. A
// rejection is a 200 with decision "rejected": the operator asked what would
// happen, and being refused is the answer.
type PreviewPolicyResponse struct {
	Decision    string          `json:"decision"`
	RequestBody json.RawMessage `json:"request_body,omitempty"`
	Status      int             `json:"status"`
	Type        string          `json:"type,omitempty"`
	Message     string          `json:"message,omitempty"`
}
