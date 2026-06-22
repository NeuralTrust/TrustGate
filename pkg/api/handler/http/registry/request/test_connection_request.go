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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type TestConnectionRequest struct {
	RegistryID      string             `json:"registry_id,omitempty"`
	Provider        string             `json:"provider,omitempty"`
	ProviderOptions map[string]any     `json:"provider_options,omitempty"`
	Auth            *TargetAuthRequest `json:"auth,omitempty"`
}

func (r TestConnectionRequest) IsByID() bool {
	return strings.TrimSpace(r.RegistryID) != ""
}

func (r TestConnectionRequest) Validate() error {
	if r.IsByID() {
		if r.Provider != "" || r.Auth != nil {
			return fmt.Errorf("registry_id cannot be combined with provider/auth: %w", commonerrors.ErrValidation)
		}
		return nil
	}
	if strings.TrimSpace(r.Provider) == "" {
		return fmt.Errorf("provider is required when registry_id is not set: %w", commonerrors.ErrValidation)
	}
	if r.Auth == nil {
		return fmt.Errorf("auth is required when registry_id is not set: %w", commonerrors.ErrValidation)
	}
	if err := r.Auth.ToDomain().Validate(); err != nil {
		return err
	}
	return nil
}

func (r TestConnectionRequest) ToAuth() *domain.TargetAuth {
	return r.Auth.ToDomain()
}
