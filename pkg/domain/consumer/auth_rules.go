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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

func ValidateAuthType(consType Type, mode RoutingMode, authType authdomain.Type) error {
	if consType == TypeMCP && authType == authdomain.TypeOIDC {
		return fmt.Errorf(
			"%w: an MCP consumer cannot use an oidc auth; interactive MCP clients need the gateway to broker the login, which requires an oauth2 auth with a pre-registered client",
			commonerrors.ErrConflict,
		)
	}
	if mode == RoutingModeRoleBased && !authType.IsIdentityProvider() {
		return fmt.Errorf(
			"%w: a role_based consumer requires an identity-provider auth (oauth2 or oidc), got %q",
			commonerrors.ErrConflict, authType,
		)
	}
	return nil
}
