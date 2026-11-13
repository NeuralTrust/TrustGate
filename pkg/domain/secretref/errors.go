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

package secretref

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// Errors of a write that holds secret references. Each maps to a stable
// error code of the admin API.
var (
	ErrReferencesNotSupported = fmt.Errorf("this gateway cannot hold secret references: its planes are not operated by you: %w", commonerrors.ErrValidation)
	ErrUnknownStore           = fmt.Errorf("no secret store with that name is available to this gateway: %w", commonerrors.ErrValidation)
	ErrPathNotAllowed         = fmt.Errorf("the path is outside the secret store's allowed paths: %w", commonerrors.ErrValidation)
	ErrDataPlaneTooOld        = fmt.Errorf("a data plane of this gateway does not understand secret references; upgrade it first: %w", commonerrors.ErrValidation)
	ErrStoreUnverified        = fmt.Errorf("no data plane of this gateway is connected to confirm the secret store; retry with allow_unverified_secret_refs=true to save it anyway: %w", commonerrors.ErrValidation)
	ErrTestRunsOnDataPlane    = fmt.Errorf("this gateway's secret stores are configured on its data planes; test them there: %w", commonerrors.ErrConflict)
	ErrMissingScope           = fmt.Errorf("writing a secret reference requires the secret_stores:read scope: %w", commonerrors.ErrForbidden)
)
