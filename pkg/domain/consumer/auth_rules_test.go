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
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

func TestValidateAuthType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		consumer     Type
		mode         RoutingMode
		authType     authdomain.Type
		wantConflict bool
	}{
		{
			name:     "mcp accepts a validate-only identity provider",
			consumer: TypeMCP,
			mode:     RoutingModeInline,
			authType: authdomain.TypeOIDC,
		},
		{
			name:     "mcp accepts oauth2",
			consumer: TypeMCP,
			mode:     RoutingModeInline,
			authType: authdomain.TypeOAuth2,
		},
		{
			name:     "mcp accepts an api key",
			consumer: TypeMCP,
			mode:     RoutingModeInline,
			authType: authdomain.TypeAPIKey,
		},
		{
			name:     "role_based accepts an identity provider",
			consumer: TypeLLM,
			mode:     RoutingModeRoleBased,
			authType: authdomain.TypeOIDC,
		},
		{
			name:         "role_based rejects an api key",
			consumer:     TypeLLM,
			mode:         RoutingModeRoleBased,
			authType:     authdomain.TypeAPIKey,
			wantConflict: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateAuthType(tt.consumer, tt.mode, tt.authType)
			if tt.wantConflict {
				if !errors.Is(err, commonerrors.ErrConflict) {
					t.Fatalf("ValidateAuthType() error = %v, want ErrConflict", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateAuthType() error = %v, want nil", err)
			}
		})
	}
}
