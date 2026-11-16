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
	"strings"

	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// TestConnectionRequest is a policy connection test: the settings as the form
// holds them, and in edit mode the stored policy whose credentials stand in
// for masked values.
type TestConnectionRequest struct {
	Slug     string         `json:"slug" example:"google_model_armor"`
	Settings map[string]any `json:"settings"`
	PolicyID string         `json:"policy_id,omitempty" format:"uuid"`
}

// ToInput validates the request and builds the use-case input.
func (r TestConnectionRequest) ToInput(gatewayID ids.GatewayID, onDataPlane bool) (apppolicy.TestConnectionInput, error) {
	slug := strings.TrimSpace(r.Slug)
	if slug == "" {
		return apppolicy.TestConnectionInput{}, fmt.Errorf("slug is required: %w", commonerrors.ErrValidation)
	}
	if r.Settings == nil {
		return apppolicy.TestConnectionInput{}, fmt.Errorf("settings is required: %w", commonerrors.ErrValidation)
	}
	in := apppolicy.TestConnectionInput{GatewayID: gatewayID, Slug: slug, Settings: r.Settings, OnDataPlane: onDataPlane}
	if id := strings.TrimSpace(r.PolicyID); id != "" {
		policyID, err := ids.Parse[ids.PolicyKind](id)
		if err != nil {
			return apppolicy.TestConnectionInput{}, fmt.Errorf("invalid policy_id: %w", commonerrors.ErrValidation)
		}
		in.PolicyID = &policyID
	}
	return in, nil
}
