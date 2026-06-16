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

package consumer

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

var (
	ErrNotFound         = fmt.Errorf("consumer: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists    = fmt.Errorf("consumer: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents    = fmt.Errorf("consumer: %w", commonerrors.ErrHasDependents)
	ErrInvalidGatewayID = fmt.Errorf("consumer: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidAuthID    = fmt.Errorf("consumer: invalid auth_id: %w", commonerrors.ErrValidation)
	ErrInvalidName      = fmt.Errorf("consumer: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidType      = fmt.Errorf("consumer: invalid type: %w", commonerrors.ErrValidation)
	ErrInvalidSlug      = fmt.Errorf("consumer: invalid slug: %w", commonerrors.ErrValidation)

	ErrInvalidRoutingMode = fmt.Errorf("consumer: invalid routing_mode: %w", commonerrors.ErrValidation)
	ErrInvalidLBConfig    = fmt.Errorf("consumer: invalid lb_config: %w", commonerrors.ErrValidation)
	ErrSlugAlreadyExists  = fmt.Errorf("consumer: slug already exists: %w", commonerrors.ErrAlreadyExists)
	ErrInvalidFallback    = fmt.Errorf("consumer: invalid fallback: %w", commonerrors.ErrValidation)
	ErrInvalidModelPolicy = fmt.Errorf("consumer: invalid model policy: %w", commonerrors.ErrValidation)

	ErrInvalidToolkit  = fmt.Errorf("consumer: invalid toolkit: %w", commonerrors.ErrValidation)
	ErrInvalidFailMode = fmt.Errorf("consumer: invalid fail_mode: %w", commonerrors.ErrValidation)
)
