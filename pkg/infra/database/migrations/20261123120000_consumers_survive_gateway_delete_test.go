//go:build functional

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

package migrations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConsumersSurviveGatewayDeleteMigration(t *testing.T) {
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE gateways (id UUID PRIMARY KEY) ON COMMIT DROP;
		CREATE TEMP TABLE consumers (
			id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			gateway_id UUID NOT NULL CONSTRAINT consumers_gateway_id_fkey REFERENCES gateways(id) ON DELETE RESTRICT,
			deleted_at TIMESTAMPTZ NULL
		) ON COMMIT DROP;
		INSERT INTO gateways (id) VALUES ('00000000-0000-0000-0000-000000000001')`)

	const insert = `INSERT INTO consumers (gateway_id, deleted_at) VALUES ('00000000-0000-0000-0000-000000000001', NOW())`
	const fkCount = `SELECT COUNT(*) FROM pg_constraint WHERE conrelid = 'consumers'::regclass AND confrelid = 'gateways'::regclass AND contype = 'f'`
	require.Equal(t, 1, countOf(t, ctx, tx, fkCount))
	runTwice(t, ctx, tx, upConsumersSurviveGatewayDelete)
	require.Zero(t, countOf(t, ctx, tx, fkCount), "no foreign key from consumers to gateways remains")
	_, err := tx.Exec(ctx, insert)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `DELETE FROM gateways`)
	require.NoError(t, err, "a gateway row can go while its soft-deleted consumers stay")
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumers`))

	runTwice(t, ctx, tx, downConsumersSurviveGatewayDelete)
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumers`), "down drops the orphaned consumers")
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_constraint WHERE conrelid = 'consumers'::regclass AND confrelid = 'gateways'::regclass AND contype = 'f'`))
}
