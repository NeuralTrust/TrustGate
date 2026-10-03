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

// ConsumerLabelSetRequest is one traffic label set projected onto a consumer.
type ConsumerLabelSetRequest struct {
	// ID is the label set's id in the app's catalog, opaque to TrustGate.
	ID           string                 `json:"id" example:"0b9e3f2a-6c1d-4a7e-9b2f-3d4c5e6f7a8b"`
	Name         string                 `json:"name" example:"Sentiment analysis"`
	Instructions string                 `json:"instructions,omitempty" example:"Classify the overall sentiment of the user's message"`
	Labels       []ConsumerLabelRequest `json:"labels"`
}

// ConsumerLabelRequest is one of the labels of a set.
type ConsumerLabelRequest struct {
	Name        string `json:"name" example:"positive"`
	Description string `json:"description,omitempty" example:"The user is satisfied or happy"`
}
