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

package auth

import (
	"errors"
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

var (
	ErrNotFound         = fmt.Errorf("auth: %w", commonerrors.ErrNotFound)
	ErrAlreadyExists    = fmt.Errorf("auth: %w", commonerrors.ErrAlreadyExists)
	ErrHasDependents    = fmt.Errorf("auth: %w", commonerrors.ErrHasDependents)
	ErrInvalidName      = fmt.Errorf("auth: invalid name: %w", commonerrors.ErrValidation)
	ErrInvalidGatewayID = fmt.Errorf("auth: invalid gateway_id: %w", commonerrors.ErrValidation)
	ErrInvalidType      = fmt.Errorf("auth: invalid type: %w", commonerrors.ErrValidation)
	ErrInvalidConfig    = fmt.Errorf("auth: invalid config: %w", commonerrors.ErrValidation)
	// ErrExpired is a key that was real and is not any more. It wraps
	// ErrNotFound so every caller that already refuses an unknown key refuses
	// this one identically: what the holder is told must not distinguish a key
	// that expired from a key that never existed.
	ErrExpired         = fmt.Errorf("auth: api key expired: %w", commonerrors.ErrNotFound)
	ErrExpiryInThePast = fmt.Errorf("auth: expires_at is in the past: %w", commonerrors.ErrValidation)
	ErrDuplicateOAuth2 = fmt.Errorf("auth: another enabled oauth2 auth already covers this issuer and audience: %w", commonerrors.ErrAlreadyExists)
	// ErrOwnedKeyExists is a second personal key for an owner who already
	// holds one on the gateway.
	ErrOwnedKeyExists = fmt.Errorf("auth: a personal key already exists for this owner: %w", commonerrors.ErrAlreadyExists)
	// ErrOwnedKey is an admin change to a key only its owner may change.
	ErrOwnedKey = errors.New("auth: owned_key: managed by its owner")
	// ErrRotatedConcurrently is a rotation that lost the race to another one:
	// the secret it read is no longer the stored one, so it changes nothing.
	ErrRotatedConcurrently = fmt.Errorf("auth: the key was rotated by another request: %w", commonerrors.ErrConflict)
	ErrOwnedExpiry         = fmt.Errorf("auth: expires_at must be in the future and within 90 days: %w", commonerrors.ErrValidation)
	ErrInvalidOwner        = fmt.Errorf("auth: invalid owner_id: %w", commonerrors.ErrValidation)
	ErrInvalidBudget       = fmt.Errorf("auth: invalid budget: %w", commonerrors.ErrValidation)
	// ErrApplicationKey is an owner-only operation, such as a budget, asked of
	// an application key.
	ErrApplicationKey = errors.New("auth: application_key: not a personal key")
)
