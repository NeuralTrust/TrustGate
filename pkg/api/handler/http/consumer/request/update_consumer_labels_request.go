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

// UpdateConsumerLabelsRequest replaces the whole label list of a consumer. An
// empty list clears it; the field itself is required so that a body without it
// never clears the labels by accident.
type UpdateConsumerLabelsRequest struct {
	Labels []ConsumerLabelRequest `json:"labels"`
}

func (r *UpdateConsumerLabelsRequest) Validate() error {
	if r.Labels == nil {
		return fmt.Errorf("labels is required, send [] to clear: %w", commonerrors.ErrValidation)
	}
	return trafficlabel.ValidateLabels(r.ToDomain())
}

func (r *UpdateConsumerLabelsRequest) ToDomain() []trafficlabel.Label {
	out := make([]trafficlabel.Label, len(r.Labels))
	for i, l := range r.Labels {
		out[i] = trafficlabel.Label{ID: l.ID, Name: l.Name, Instructions: l.Instructions, Examples: l.Examples}
	}
	return trafficlabel.NormalizeLabels(out)
}
