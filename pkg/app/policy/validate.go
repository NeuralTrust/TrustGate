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

package policy

import (
	"errors"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

func validatePlugin(reg appplugins.Registry, slug string, stages []domain.Stage, settings map[string]any) error {
	if err := reg.ValidateStages(slug, stages); err != nil {
		return errors.Join(commonerrors.ErrValidation, err)
	}
	if err := reg.Validate(slug, settings); err != nil {
		return errors.Join(commonerrors.ErrValidation, err)
	}
	return nil
}
