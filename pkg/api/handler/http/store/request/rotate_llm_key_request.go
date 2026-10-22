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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// RotateLLMKeyRequest is the body of a personal key rotation.
type RotateLLMKeyRequest struct {
	// ExpiresAt is the new expiry, within the next 366 days. Absent keeps the
	// current one, which a key that has expired cannot.
	ExpiresAt string `json:"expires_at,omitempty" format:"date-time" example:"2026-12-31T12:00:00Z"`
	// NeverExpires renews the key with no expiry at all. Not allowed with
	// expires_at.
	NeverExpires bool `json:"never_expires,omitempty" example:"false"`
}

// Expiry is the expiry change the rotation asks for: nil keeps the current
// expiry, a change with no At clears it.
func (r RotateLLMKeyRequest) Expiry() (*appauth.ExpiryChange, error) {
	at, err := httpio.ParseExpiresAt(r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	switch {
	case r.NeverExpires && at != nil:
		return nil, fmt.Errorf("expires_at and never_expires cannot be combined: %w", commonerrors.ErrValidation)
	case r.NeverExpires:
		return &appauth.ExpiryChange{}, nil
	case at != nil:
		return &appauth.ExpiryChange{At: at}, nil
	default:
		return nil, nil
	}
}
