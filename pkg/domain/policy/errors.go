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
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

var (
	ErrNotFound          = fmt.Errorf("policy: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists     = fmt.Errorf("policy: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents     = fmt.Errorf("policy: %w", commonerrors.ErrHasDependents)
	ErrInvalidName       = fmt.Errorf("policy: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidGatewayID  = fmt.Errorf("policy: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidConsumerID = fmt.Errorf("policy: invalid consumer_id: %w", commonerrors.ErrValidation)
	ErrInvalidSlug       = fmt.Errorf("policy: invalid slug: %w", commonerrors.ErrValidation)
	ErrInvalidStage      = fmt.Errorf("policy: invalid stage: %w", commonerrors.ErrValidation)
	ErrInvalidMode       = fmt.Errorf("policy: invalid mode: %w", commonerrors.ErrValidation)
	ErrInvalidPriority   = fmt.Errorf("policy: invalid priority: %w", commonerrors.ErrValidation)
)
