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

// ValidateAuthType rejects auth types a consumer of the given type cannot use.
// Every other combination is allowed: an API key, a bearer JWT validated against
// an external IdP (oauth2 / oidc) or a client certificate all identify the
// application; who the application acts for is the consumer's Identity, not
// its auth (see Identity).
func ValidateAuthType(consType Type, authType authdomain.Type) error {
	if consType == TypeMCP && authType == authdomain.TypeOIDC {
		return fmt.Errorf(
			"%w: an MCP consumer cannot use an oidc auth; interactive MCP clients need the gateway to broker the login, which requires an oauth2 auth with a pre-registered client",
			commonerrors.ErrConflict,
		)
	}
	return nil
}

// ValidateAuth rejects an auth type the consumer cannot use given its type and
// identity. A consumer acting for platform users is entered by people who sign
// in, so only an oauth2 auth (or none, which leaves the built-in identity
// provider) fits; a consumer whose application names its own end users
// authenticates as a machine, so only an API key or a client certificate fits.
func ValidateAuth(c *Consumer, authType authdomain.Type) error {
	if c == nil {
		return nil
	}
	if err := ValidateAuthType(c.Type, authType); err != nil {
		return err
	}
	switch {
	case c.Identity.PlatformUsers():
		if authType != authdomain.TypeOAuth2 {
			return fmt.Errorf(
				"%w: a consumer that acts for platform users needs its users to sign in, so it can only use an oauth2 auth (or none, for the built-in identity provider), not %s",
				commonerrors.ErrConflict, authType,
			)
		}
	case c.Identity.AppUsers():
		if authType != authdomain.TypeAPIKey && authType != authdomain.TypeMTLS {
			return fmt.Errorf(
				"%w: a consumer whose application identifies its end users authenticates as a machine, so it can only use an api_key or mtls auth, not %s",
				commonerrors.ErrConflict, authType,
			)
		}
	}
	return nil
}
