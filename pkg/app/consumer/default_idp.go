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

import authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"

// DefaultIdPAdmitted reports whether a path with these matches may be entered
// through the built-in identity provider. The request-time auth chain, the
// authorize path and the protected-resource metadata all ask it, so a login
// is never brokered for a consumer that would then refuse its session.
//
// The built-in provider bootstraps consumers whose users sign in and that
// carry no identity provider of their own. Two things exclude it. Any oauth2
// auth or enabled credential on the path (an api key, mTLS, its own IdP) is
// then the only way in: falling back here would let any platform login reach
// the consumer without it. And a consumer that is not entered by a person
// (acts_for_users off, or the app source, where the application authenticates
// as itself and names its end users) must not be rescued when it holds no
// credential: revoking its last api key would otherwise not lock it down but
// open it up, since an empty auth binding accepts any client the provider
// verifies.
func DefaultIdPAdmitted(matches []PathMatch) bool {
	signIn := false
	for _, m := range matches {
		if m.Consumer.WantsSignIn() {
			signIn = true
		}
		for _, a := range m.Auths {
			if a.Enabled || a.Type == authdomain.TypeOAuth2 {
				return false
			}
		}
	}
	return signIn
}
