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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// CreateLLMKeyRequest is the body of a personal key create.
type CreateLLMKeyRequest struct {
	ExpiresAt string `json:"expires_at" format:"date-time" example:"2026-12-31T12:00:00Z"`
}

// Expiry parses expires_at, which a personal key cannot leave out.
func (r CreateLLMKeyRequest) Expiry() (time.Time, error) {
	at, err := httpio.ParseExpiresAt(r.ExpiresAt)
	if err != nil {
		return time.Time{}, err
	}
	if at == nil {
		return time.Time{}, fmt.Errorf("expires_at is required: %w", commonerrors.ErrValidation)
	}
	return *at, nil
}
