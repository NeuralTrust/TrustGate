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

package costcap

// CostCapData is the per-request telemetry emitted by the cost cap plugin.
type CostCapData struct {
	Stage            string  `json:"stage"`
	Provider         string  `json:"provider,omitempty"`
	Model            string  `json:"model,omitempty"`
	Violation        bool    `json:"violation,omitempty"`
	UnknownModel     bool    `json:"unknown_model,omitempty"`
	Downgraded       bool    `json:"downgraded,omitempty"`
	InputPricePer1k  float64 `json:"input_price_per_1k,omitempty"`
	OutputPricePer1k float64 `json:"output_price_per_1k,omitempty"`
	MaxInputPer1k    float64 `json:"max_input_per_1k,omitempty"`
	MaxOutputPer1k   float64 `json:"max_output_per_1k,omitempty"`
}
