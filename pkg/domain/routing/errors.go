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

package routing

import (
	"errors"
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

var (
	ErrInvalidModelRef  = fmt.Errorf("routing: invalid model reference: %w", commonerrors.ErrValidation)
	ErrUnknownPoolAlias = fmt.Errorf("routing: unknown pool alias: %w", commonerrors.ErrValidation)
	// ErrAmbiguousModel is retained for source compatibility.
	// Deprecated: short model references now pin the first eligible registry.
	ErrAmbiguousModel = fmt.Errorf("routing: ambiguous model: %w", commonerrors.ErrValidation)
	ErrModelDenied      = errors.New("routing: model denied")
)
