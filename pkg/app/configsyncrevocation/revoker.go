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

package configsyncrevocation

import (
	"context"
	"fmt"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
)

// maxIssuedBeforeAhead only absorbs clock skew between the token issuer and
// this control plane. Callers send the replacement token's own iat, which the
// issuer already backdates, so a legitimate mark is never ahead of now; a mark
// further ahead would also revoke tokens minted after the request.
const maxIssuedBeforeAhead = 5 * time.Second

//go:generate mockery --name=Revoker --dir=. --output=./mocks --filename=configsyncrevocation_revoker_mock.go --case=underscore --with-expecter

// Revoker records config-sync token revocations for one scope.
type Revoker interface {
	// Revoke revokes the listed jtis and, when issuedBefore is set, every
	// token of the scope issued before that unix time.
	Revoke(ctx context.Context, scope string, jtis []string, issuedBefore int64) error
}

var _ Revoker = (*revoker)(nil)

type revoker struct {
	store domain.Store
	now   func() time.Time
}

// NewRevoker returns the use case that validates a revocation request and
// records it in store. now supplies the clock for the future-mark bound.
func NewRevoker(store domain.Store, now func() time.Time) Revoker {
	return &revoker{store: store, now: now}
}

func (r *revoker) Revoke(ctx context.Context, scope string, jtis []string, issuedBefore int64) error {
	if scope == "" {
		return fmt.Errorf("config-sync revocation: scope is required: %w", commonerrors.ErrValidation)
	}
	if len(jtis) == 0 && issuedBefore == 0 {
		return fmt.Errorf("config-sync revocation: send jtis or issued_before: %w", commonerrors.ErrValidation)
	}
	if issuedBefore < 0 {
		return fmt.Errorf("config-sync revocation: issued_before must be positive: %w", commonerrors.ErrValidation)
	}
	if limit := r.now().Add(maxIssuedBeforeAhead).Unix(); issuedBefore > limit {
		return fmt.Errorf("config-sync revocation: issued_before is more than %s ahead: %w", maxIssuedBeforeAhead, commonerrors.ErrValidation)
	}
	return r.store.Apply(ctx, domain.Revocation{
		Scope:        scope,
		JTIs:         uniqueJTIs(jtis),
		IssuedBefore: issuedBefore,
	})
}

func uniqueJTIs(jtis []string) []string {
	if len(jtis) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(jtis))
	out := make([]string, 0, len(jtis))
	for _, jti := range jtis {
		if _, dup := seen[jti]; dup {
			continue
		}
		seen[jti] = struct{}{}
		out = append(out, jti)
	}
	return out
}
