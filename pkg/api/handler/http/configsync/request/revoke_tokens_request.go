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
	"unicode"
	"unicode/utf8"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

const (
	maxRevokeJTIs   = 100
	maxRevokeJTILen = 128
)

// RevokeTokensRequest names the config-sync tokens of one gateway to revoke.
// JTIs lists token identifiers. IssuedBefore is a unix time in seconds that
// revokes every token issued strictly before it. At least one of the two is
// required. A token whose iat equals issued_before is not revoked, so send the
// iat of the replacement token as issued_before.
type RevokeTokensRequest struct {
	JTIs         []string `json:"jtis"`
	IssuedBefore *int64   `json:"issued_before"`
}

// Validate checks the shape of the body. The bound on how far issued_before may
// lie in the future is checked by the use case, which owns the clock.
func (r RevokeTokensRequest) Validate() error {
	if r.JTIs == nil && r.IssuedBefore == nil {
		return fmt.Errorf("send jtis or issued_before: %w", commonerrors.ErrValidation)
	}
	if r.JTIs != nil {
		if len(r.JTIs) < 1 || len(r.JTIs) > maxRevokeJTIs {
			return fmt.Errorf("jtis must have between 1 and %d entries: %w", maxRevokeJTIs, commonerrors.ErrValidation)
		}
		for _, jti := range r.JTIs {
			if jti == "" || len(jti) > maxRevokeJTILen {
				return fmt.Errorf("each jti must be between 1 and %d bytes: %w", maxRevokeJTILen, commonerrors.ErrValidation)
			}
			if !utf8.ValidString(jti) || strings.ContainsFunc(jti, unicode.IsControl) {
				return fmt.Errorf("each jti must be printable UTF-8: %w", commonerrors.ErrValidation)
			}
		}
	}
	if r.IssuedBefore != nil && *r.IssuedBefore <= 0 {
		return fmt.Errorf("issued_before must be greater than 0: %w", commonerrors.ErrValidation)
	}
	return nil
}
