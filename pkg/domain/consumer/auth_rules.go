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

// ValidateAuth rejects an auth type the consumer cannot use given its type and
// identity. A consumer acting for platform users is entered by people who sign
// in, so only an oauth2 auth (or none, which leaves the built-in identity
// provider) fits; a consumer whose application names its own end users
// authenticates as a machine, so only an API key or a client certificate fits.
func ValidateAuth(c *Consumer, authType authdomain.Type) error {
	if c == nil {
		return nil
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

// ValidateAuthConfig is ValidateAuth plus the checks that need the auth's
// configuration: a consumer whose users sign in can only use an identity
// provider that can broker that login (an oauth2 config with a registered
// client), not a validation-only one.
func ValidateAuthConfig(c *Consumer, au *authdomain.Auth) error {
	if c == nil || au == nil {
		return nil
	}
	if err := ValidateAuth(c, au.Type); err != nil {
		return err
	}
	if c.Identity.PlatformUsers() && au.Type == authdomain.TypeOAuth2 && !au.Config.OAuth2.Interactive() {
		return fmt.Errorf(
			"%w: users sign in through this consumer's identity provider, so it needs a client registered at the provider (client_id); a token-validation-only provider cannot broker the login",
			commonerrors.ErrConflict,
		)
	}
	return nil
}
