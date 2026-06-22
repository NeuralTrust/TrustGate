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

package modelallowlist

const (
	decisionAllowed         = "allowed"
	decisionRejected        = "rejected"
	decisionSubstituted     = "substituted"
	decisionDefaulted       = "defaulted"
	decisionWouldReject     = "would_reject"
	decisionWouldSubstitute = "would_substitute"
)

type ModelAllowlistData struct {
	RequestedModel  string `json:"requested_model"`
	Decision        string `json:"decision"`
	MatchedPattern  string `json:"matched_pattern,omitempty"`
	SubstitutedWith string `json:"substituted_with,omitempty"`
	Behavior        string `json:"behavior"`
}

func observeDecision(b behavior) string {
	if b == behaviorSubstitute {
		return decisionWouldSubstitute
	}
	return decisionWouldReject
}
