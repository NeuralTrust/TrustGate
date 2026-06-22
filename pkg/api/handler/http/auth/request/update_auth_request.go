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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

type UpdateAuthRequest struct {
	Name    *string        `json:"name,omitempty"`
	Type    *string        `json:"type,omitempty"`
	Enabled *bool          `json:"enabled,omitempty"`
	Config  *ConfigRequest `json:"config,omitempty"`
}

func (r UpdateAuthRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	if r.Type != nil && strings.TrimSpace(*r.Type) == "" {
		return fmt.Errorf("type is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateAuthRequest) ToType() *domain.Type {
	if r.Type == nil {
		return nil
	}
	t := domain.Type(*r.Type)
	return &t
}

func (r UpdateAuthRequest) ToConfig() *domain.Config {
	if r.Config == nil {
		return nil
	}
	cfg := r.Config.ToDomain()
	return &cfg
}
