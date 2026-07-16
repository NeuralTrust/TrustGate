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

package ratelimit

import (
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// ErrInstanceLimit is returned when a tenant already has the tier's max instances.
var ErrInstanceLimit = fmt.Errorf("ratelimit: instance limit reached: %w", commonerrors.ErrConflict)
