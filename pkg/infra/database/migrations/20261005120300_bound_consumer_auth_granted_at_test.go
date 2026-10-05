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

func TestBoundConsumerAuthGrantedAtMigration(t *testing.T) {
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE consumer_auth (consumer_id UUID NOT NULL, auth_id UUID NOT NULL, PRIMARY KEY (consumer_id, auth_id)) ON COMMIT DROP`)
	require.NoError(t, upAddConsumerAuthGrant(ctx, tx))
	_, err := tx.Exec(ctx, `
		INSERT INTO consumer_auth (consumer_id, auth_id, level, priority, granted_at) VALUES
			(gen_random_uuid(), gen_random_uuid(), 'user', 1, '0001-01-01 00:00:00+00 BC'),
			(gen_random_uuid(), gen_random_uuid(), 'user', 1, '10000-01-01 04:00:00+00'),
			(gen_random_uuid(), gen_random_uuid(), 'user', 1, '2026-10-01 09:00:00+00'),
			(gen_random_uuid(), gen_random_uuid(), NULL, NULL, NULL)`)
	require.NoError(t, err)

	runTwice(t, ctx, tx, upBoundConsumerAuthGrantedAt)
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumer_auth WHERE granted_at = TIMESTAMPTZ '1970-01-01 00:00:00+00'`))
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumer_auth WHERE granted_at = TIMESTAMPTZ '9999-12-31 23:59:59.999999+00'`))
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumer_auth WHERE granted_at = TIMESTAMPTZ '2026-10-01 09:00:00+00'`))

	const insert = `INSERT INTO consumer_auth (consumer_id, auth_id, level, priority, granted_at) VALUES (gen_random_uuid(), gen_random_uuid(), 'group', 1, $1::timestamptz)`
	for name, tc := range map[string]struct {
		grantedAt string
		state     string
	}{
		"year 0000":               {"0001-01-01 00:00:00+00 BC", "23514"},
		"before the unix epoch":   {"1969-12-31 23:59:59.999999+00", "23514"},
		"at the unix epoch":       {"1970-01-01 00:00:00+00", ""},
		"valid instant at -05:00": {"2026-10-01 04:00:00-05", ""},
		"last microsecond 9999":   {"9999-12-31 23:59:59.999999+00", ""},
		"near 9999 at -05:00":     {"9999-12-31 23:00:00-05", "23514"},
		"infinity":                {"infinity", "23514"},
		"minus infinity":          {"-infinity", "23514"},
	} {
		require.Equal(t, tc.state, sqlStateOf(t, ctx, tx, insert, tc.grantedAt), name)
	}

	runTwice(t, ctx, tx, downBoundConsumerAuthGrantedAt)
	require.Empty(t, sqlStateOf(t, ctx, tx, insert, "1969-12-31 23:59:59+00"))
	require.Equal(t, "23514", sqlStateOf(t, ctx, tx, insert, "infinity"))
	require.Equal(t, 4, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumer_auth`))
}
