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

package regexreplace

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

const (
	decisionRewritten = "rewritten"
	decisionObserved  = "observed"
	decisionNoMatch   = "no_match"
)

type Data struct {
	Target   string `json:"target,omitempty"`
	Stage    string `json:"stage,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Decision string `json:"decision,omitempty"`
	Changed  bool   `json:"changed,omitempty"`
}

func setExtras(event *metrics.EventContext, data *Data) {
	if event == nil || data == nil {
		return
	}
	event.SetExtras(data)
}
