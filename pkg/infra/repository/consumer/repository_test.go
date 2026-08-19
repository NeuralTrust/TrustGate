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

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestMapPgError_RoutingConflict(t *testing.T) {
	t.Parallel()
	err := mapPgError(&pgconn.PgError{Code: pgRoutingConflict, Message: "routing_mode_conflict"})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestMapPgError_RoutingModeCheck(t *testing.T) {
	t.Parallel()
	err := mapPgError(&pgconn.PgError{Code: pgCheckViolation, ConstraintName: consumerRoutingModeCheck})
	if !errors.Is(err, domain.ErrInvalidRoutingMode) {
		t.Fatalf("err = %v, want ErrInvalidRoutingMode", err)
	}
}

func TestNullableProtocolAcceptance(t *testing.T) {
	t.Parallel()
	if got := nullableProtocolAcceptance(""); got != nil {
		t.Fatalf("empty = %v, want nil", got)
	}
	if got := nullableProtocolAcceptance(domain.ProtocolAcceptanceLegacyOnly); got != "legacy_only" {
		t.Fatalf("legacy_only = %v, want legacy_only", got)
	}
}

func TestMCPPolicyFromColumns_ProtocolAcceptance(t *testing.T) {
	t.Parallel()

	t.Run("empty columns yield nil policy", func(t *testing.T) {
		t.Parallel()
		got, err := mcpPolicyFromColumns(nil, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("got %+v, want nil", got)
		}
	})

	t.Run("hydrates protocol_acceptance without toolkit JSON", func(t *testing.T) {
		t.Parallel()
		got, err := mcpPolicyFromColumns(nil, "open", "legacy_only")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ProtocolAcceptance != domain.ProtocolAcceptanceLegacyOnly {
			t.Fatalf("ProtocolAcceptance = %v, want legacy_only", got)
		}
		if got.FailMode != domain.FailModeOpen {
			t.Fatalf("FailMode = %q, want open", got.FailMode)
		}
	})

	t.Run("toolkit JSON does not host protocol_acceptance", func(t *testing.T) {
		t.Parallel()
		got, err := mcpPolicyFromColumns([]byte(`[{"registry_id":"00000000-0000-0000-0000-000000000001","tool":"*"}]`), "", "dual_era")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.ProtocolAcceptance != domain.ProtocolAcceptanceDualEra {
			t.Fatalf("ProtocolAcceptance = %v, want dual_era", got)
		}
		if len(got.Toolkit) != 1 {
			t.Fatalf("toolkit len = %d, want 1", len(got.Toolkit))
		}
	})
}
