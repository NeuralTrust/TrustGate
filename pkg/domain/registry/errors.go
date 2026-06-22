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

package registry

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

var (
	ErrNotFound               = fmt.Errorf("registry: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists          = fmt.Errorf("registry: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents          = fmt.Errorf("registry: %w", commonerrors.ErrHasDependents)
	ErrInvalidGatewayID       = fmt.Errorf("registry: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidRegistryID      = fmt.Errorf("registry: invalid registry_id: %w", commonerrors.ErrValidation)
	ErrInvalidEmbeddingConfig = fmt.Errorf("registry: invalid embedding config: %w", commonerrors.ErrValidation)
	ErrInvalidRegistry        = fmt.Errorf("registry: invalid backend: %w", commonerrors.ErrValidation)
	ErrInvalidHealthChecks    = fmt.Errorf("registry: invalid health checks: %w", commonerrors.ErrValidation)
	ErrInvalidMCPTarget       = fmt.Errorf("registry: invalid mcp target: %w", commonerrors.ErrValidation)
)
