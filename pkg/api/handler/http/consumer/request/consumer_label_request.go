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

// ConsumerLabelRequest is one traffic label projected onto a consumer.
type ConsumerLabelRequest struct {
	// ID is the label's id in the app's catalog, opaque to TrustGate.
	ID           string   `json:"id" example:"0b9e3f2a-6c1d-4a7e-9b2f-3d4c5e6f7a8b"`
	Name         string   `json:"name" example:"Billing"`
	Instructions string   `json:"instructions" example:"Questions about invoices, charges and refunds."`
	Examples     []string `json:"examples,omitempty"`
}
