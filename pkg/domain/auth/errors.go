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

package auth

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

var (
	ErrNotFound         = fmt.Errorf("auth config not found; verify the auth id and gateway_id: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists    = fmt.Errorf("auth config already exists; use a unique name or update the existing config: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents    = fmt.Errorf("auth config has dependents; detach consumers that reference it first: %w", commonerrors.ErrHasDependents)
	ErrInvalidName      = fmt.Errorf("auth: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidGatewayID = fmt.Errorf("auth: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidType      = fmt.Errorf("auth: invalid type: %w", commonerrors.ErrValidation)
	ErrInvalidConfig    = fmt.Errorf("auth: invalid config: %w", commonerrors.ErrValidation)
	ErrDuplicateOAuth2  = fmt.Errorf("auth: another enabled oauth2 auth already covers this issuer and audience: %w", commonerrors.ErrAlreadyExists)
)