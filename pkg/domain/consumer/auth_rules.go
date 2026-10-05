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

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

// ValidateAuth rejects an auth type the consumer cannot use.
//
// It used to reject by what the consumer declared about its callers, which is
// no longer declared: an application may be entered by a machine credential and
// by a person's token at once, and who a request runs as is read from the
// request. The credentials a consumer holds are now the declaration, so there
// is nothing left to contradict — every auth type fits every consumer, and the
// rest of the check lives in ValidateAuthConfig.
func ValidateAuth(c *Consumer, authType authdomain.Type) error {
	_, _ = c, authType
	return nil
}

// ValidateAuthConfig is ValidateAuth plus the checks that need the auth itself:
// a personal consumer takes only owned keys and an application consumer only
// unowned auths, else ErrAudienceMismatch. It is the one place rules about a
// consumer's credentials go.
func ValidateAuthConfig(c *Consumer, au *authdomain.Auth) error {
	if c == nil || au == nil {
		return nil
	}
	if c.IsPersonal() && !au.IsOwned() {
		return fmt.Errorf("%w: a personal consumer takes only owned keys", ErrAudienceMismatch)
	}
	if !c.IsPersonal() && au.IsOwned() {
		return fmt.Errorf("%w: an application consumer takes no owned keys", ErrAudienceMismatch)
	}
	return ValidateAuth(c, au.Type)
}
