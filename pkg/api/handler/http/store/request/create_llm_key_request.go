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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
)

// CreateLLMKeyRequest is the body of a personal key create.
type CreateLLMKeyRequest struct {
	// ExpiresAt is when the key stops working, within the next 366 days.
	// Absent, null or empty: it never expires.
	ExpiresAt string `json:"expires_at,omitempty" format:"date-time" example:"2026-12-31T12:00:00Z"`
}

// Expiry parses expires_at, nil for a key that never expires.
func (r CreateLLMKeyRequest) Expiry() (*time.Time, error) {
	return httpio.ParseExpiresAt(r.ExpiresAt)
}

// CreateUserLLMKeyRequest is the body of a personal key an admin creates for a
// user: the same expiry, and the email the key's calls are shown under.
type CreateUserLLMKeyRequest struct {
	CreateLLMKeyRequest
	OwnerEmail string `json:"owner_email,omitempty" example:"alice@example.com"`
}
