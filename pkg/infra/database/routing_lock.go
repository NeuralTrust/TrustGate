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

package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/jackc/pgx/v5"
)

// LockGatewayRouting orders routing writes before locking individual consumers.
func LockGatewayRouting(ctx context.Context, tx pgx.Tx, gatewayID ids.GatewayID) error {
	var id ids.GatewayID
	err := tx.QueryRow(ctx, `SELECT id FROM gateways WHERE id = $1 FOR UPDATE`, gatewayID).Scan(&id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lock gateway routing: %w", err)
	}
	return nil
}
