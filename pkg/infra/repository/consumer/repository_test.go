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

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
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
