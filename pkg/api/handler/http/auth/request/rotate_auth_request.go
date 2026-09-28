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

package request

import (
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
)

// RotateAuthRequest is the optional body of a rotation.
//
// Rotating with no body replaces the secret and nothing else, expiry included:
// a key with three weeks left keeps them. Sending expires_at is how the new
// secret gets a window of its own — an empty string for none.
type RotateAuthRequest struct {
	ExpiresAt *string `json:"expires_at,omitempty"`
}

func (r RotateAuthRequest) Validate() error {
	_, err := expiryChange(r.ExpiresAt)
	return err
}

func (r RotateAuthRequest) ToExpiry() *appauth.ExpiryChange {
	change, err := expiryChange(r.ExpiresAt)
	if err != nil {
		return nil
	}
	return change
}
