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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

type UpdateConsumerRequest struct {
	Name          *string                `json:"name,omitempty"`
	Type          *string                `json:"type,omitempty"`
	RoutingMode   *string                `json:"routing_mode,omitempty"`
	LBConfig      *LBConfigRequest       `json:"lb_config,omitempty"`
	Headers       *map[string]string     `json:"headers,omitempty"`
	Active        *bool                  `json:"active,omitempty"`
	Fallback      *FallbackRequest       `json:"fallback,omitempty"`
	ModelPolicies *[]ModelPolicyRequest  `json:"model_policies,omitempty"`
	Toolkit       *[]ToolkitEntryRequest `json:"toolkit,omitempty"`
	FailMode      *string                `json:"fail_mode,omitempty"`
}

func (r UpdateConsumerRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	return nil
}

func (r UpdateConsumerRequest) ToType() *domain.Type {
	if r.Type == nil || strings.TrimSpace(*r.Type) == "" {
		return nil
	}
	t := domain.Type(strings.ToUpper(strings.TrimSpace(*r.Type)))
	return &t
}

func (r UpdateConsumerRequest) ToRoutingMode() *domain.RoutingMode {
	if r.RoutingMode == nil || strings.TrimSpace(*r.RoutingMode) == "" {
		return nil
	}
	mode := domain.NewRoutingMode(*r.RoutingMode)
	return &mode
}

func (r UpdateConsumerRequest) ToLBConfig() (*domain.LBConfig, error) {
	return r.LBConfig.ToDomain()
}

func (r UpdateConsumerRequest) ToFallback() (*domain.Fallback, error) {
	return r.Fallback.ToFallback()
}

func (r UpdateConsumerRequest) ToModelPolicies() (*domain.ModelPolicies, error) {
	if r.ModelPolicies == nil {
		return nil, nil
	}
	mp, err := parseModelPolicies(*r.ModelPolicies)
	if err != nil {
		return nil, err
	}
	return &mp, nil
}

func (r UpdateConsumerRequest) ToToolkit() (*domain.Toolkit, error) {
	if r.Toolkit == nil {
		return nil, nil
	}
	tk, err := parseToolkit(*r.Toolkit)
	if err != nil {
		return nil, err
	}
	return &tk, nil
}

func (r UpdateConsumerRequest) ToFailMode() *domain.FailMode {
	if r.FailMode == nil || strings.TrimSpace(*r.FailMode) == "" {
		return nil
	}
	m := domain.FailMode(*r.FailMode)
	return &m
}
