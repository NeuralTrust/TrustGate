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

package httpio

import (
	"fmt"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

func TestSecretReferenceErrorCodes(t *testing.T) {
	t.Parallel()
	tests := map[error]struct {
		status int
		code   string
	}{
		secretref.ErrInvalidReference:       {400, "invalid_secret_reference"},
		secretref.ErrReferencesDisabled:     {422, "secret_references_disabled"},
		secretref.ErrReferencesNotSupported: {422, "secret_references_not_supported"},
		secretref.ErrUnknownStore:           {422, "unknown_secret_store"},
		secretref.ErrPathNotAllowed:         {422, "secret_path_not_allowed"},
		secretref.ErrDataPlaneTooOld:        {422, "data_plane_too_old"},
		secretref.ErrStoreUnverified:        {422, "secret_store_unverified"},
		secretref.ErrMissingScope:           {403, "missing_scope"},
	}
	for sentinel, want := range tests {
		status, body := MapDomainError(fmt.Errorf("llm_target.auth.api_key.api_key: %w", sentinel))
		if status != want.status || body.Error != want.code {
			t.Errorf("%v -> %d %s, want %d %s", sentinel, status, body.Error, want.status, want.code)
		}
	}
}
