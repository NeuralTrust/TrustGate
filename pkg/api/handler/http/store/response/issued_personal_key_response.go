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

package response

import appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"

// IssuedPersonalKeyResponse is a personal key with its secret, returned only
// when the secret is minted. The secret is api_key, as on the admin auth
// responses.
type IssuedPersonalKeyResponse struct {
	PersonalKeyResponse
	APIKey string `json:"api_key"`
}

// FromIssuedPersonalKey maps a key that was just created or rotated.
func FromIssuedPersonalKey(key *appauth.PersonalKey) IssuedPersonalKeyResponse {
	return IssuedPersonalKeyResponse{PersonalKeyResponse: FromPersonalKey(key), APIKey: key.Auth.RawKey}
}
