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

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
)

// UpdateConsumerLabelSetsRequest replaces all the label sets of a consumer.
// An empty list clears them; the field itself is required so that a body
// without it never clears the label sets by accident.
type UpdateConsumerLabelSetsRequest struct {
	LabelSets []ConsumerLabelSetRequest `json:"label_sets"`
}

func (r *UpdateConsumerLabelSetsRequest) Validate() error {
	if r.LabelSets == nil {
		return fmt.Errorf("label_sets is required, send [] to clear: %w", commonerrors.ErrValidation)
	}
	return trafficlabel.ValidateLabelSets(r.ToDomain())
}

func (r *UpdateConsumerLabelSetsRequest) ToDomain() []trafficlabel.LabelSet {
	out := make([]trafficlabel.LabelSet, len(r.LabelSets))
	for i, s := range r.LabelSets {
		out[i] = trafficlabel.LabelSet{ID: s.ID, Name: s.Name, Instructions: s.Instructions}
		if s.Labels != nil {
			out[i].Labels = make([]trafficlabel.Label, len(s.Labels))
			for j, l := range s.Labels {
				out[i].Labels[j] = trafficlabel.Label{Name: l.Name, Description: l.Description}
			}
		}
	}
	return trafficlabel.NormalizeLabelSets(out)
}
