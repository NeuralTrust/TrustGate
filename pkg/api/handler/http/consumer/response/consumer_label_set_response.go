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

import "github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"

// ConsumerLabelSetResponse is one traffic label set held by a consumer.
type ConsumerLabelSetResponse struct {
	ID           string                  `json:"id"`
	Name         string                  `json:"name"`
	Instructions string                  `json:"instructions"`
	Labels       []ConsumerLabelResponse `json:"labels"`
}

// ConsumerLabelResponse is one of the labels of a set.
type ConsumerLabelResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func fromLabelSets(sets []trafficlabel.LabelSet) []ConsumerLabelSetResponse {
	out := make([]ConsumerLabelSetResponse, len(sets))
	for i, s := range sets {
		labels := make([]ConsumerLabelResponse, len(s.Labels))
		for j, l := range s.Labels {
			labels[j] = ConsumerLabelResponse{Name: l.Name, Description: l.Description}
		}
		out[i] = ConsumerLabelSetResponse{ID: s.ID, Name: s.Name, Instructions: s.Instructions, Labels: labels}
	}
	return out
}
