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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

type UpdatePolicyRequest struct {
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Slug        *string         `json:"slug,omitempty"`
	Enabled     *bool           `json:"enabled,omitempty"`
	Priority    *int            `json:"priority,omitempty"`
	Parallel    *bool           `json:"parallel,omitempty"`
	Settings    *map[string]any `json:"settings,omitempty"`
	Stages      *[]string       `json:"stages,omitempty"`
	Mode        *string         `json:"mode,omitempty"`
}

func (r UpdatePolicyRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	if r.Description != nil && len(*r.Description) > maxPolicyDescriptionLen {
		return fmt.Errorf("description too long (max %d): %w", maxPolicyDescriptionLen, commonerrors.ErrValidation)
	}
	if r.Slug != nil && strings.TrimSpace(*r.Slug) == "" {
		return fmt.Errorf("slug is required: %w", commonerrors.ErrValidation)
	}
	if r.Mode != nil {
		return validateMode(*r.Mode)
	}
	return nil
}

func (r UpdatePolicyRequest) ToStages() *[]domain.Stage {
	if r.Stages == nil {
		return nil
	}
	stages := toStages(*r.Stages)
	return &stages
}

func (r UpdatePolicyRequest) ToMode() *domain.Mode {
	if r.Mode == nil {
		return nil
	}
	m := domain.Mode(*r.Mode)
	return &m
}
