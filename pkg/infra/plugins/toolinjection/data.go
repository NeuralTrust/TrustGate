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

package toolinjection

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type ToolInjectionData struct {
	Stage        string            `json:"stage"`
	Injected     []InjectedOutcome `json:"injected,omitempty"`
	Rejected     bool              `json:"rejected,omitempty"`
	RejectedName string            `json:"rejected_name,omitempty"`
}

type InjectedOutcome struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}

func data(stage string, outcomes []injectOutcome) ToolInjectionData {
	d := ToolInjectionData{Stage: stage}
	for i := range outcomes {
		d.Injected = append(d.Injected, InjectedOutcome{Name: outcomes[i].Name, Outcome: outcomes[i].Outcome})
	}
	return d
}

func rejectData(stage, name string) ToolInjectionData {
	return ToolInjectionData{Stage: stage, Rejected: true, RejectedName: name}
}

func setExtras(event *metrics.EventContext, data ToolInjectionData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}
