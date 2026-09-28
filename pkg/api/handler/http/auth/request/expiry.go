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
	"strings"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// parseExpiresAt reads an RFC 3339 instant out of the wire.
//
// The empty string is the only way to say "no expiry" on a request that omits
// the field to mean "leave it alone": an absent field and a null one are the
// same thing to encoding/json, so a third word was needed for clearing.
func parseExpiresAt(raw string) (*time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("expires_at must be an RFC 3339 instant: %w", commonerrors.ErrValidation)
	}
	utc := at.UTC()
	return &utc, nil
}

// expiryChange maps an optional wire field onto the change the service takes:
// absent leaves the stored expiry alone, an empty string clears it, and an
// instant sets it.
func expiryChange(raw *string) (*appauth.ExpiryChange, error) {
	if raw == nil {
		return nil, nil
	}
	at, err := parseExpiresAt(*raw)
	if err != nil {
		return nil, err
	}
	return &appauth.ExpiryChange{At: at}, nil
}
