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
	"time"

	"github.com/stretchr/testify/require"
)

func TestAddConsumerAuthGrantMigration(t *testing.T) {
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE consumer_auth (consumer_id UUID NOT NULL, auth_id UUID NOT NULL, PRIMARY KEY (consumer_id, auth_id)) ON COMMIT DROP;
		INSERT INTO consumer_auth VALUES (gen_random_uuid(), gen_random_uuid()), (gen_random_uuid(), gen_random_uuid())`)

	runTwice(t, ctx, tx, upAddConsumerAuthGrant)
	require.Equal(t, 2, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumer_auth WHERE level IS NULL AND priority IS NULL AND granted_at IS NULL`))

	const insert = `INSERT INTO consumer_auth (consumer_id, auth_id, level, priority, granted_at) VALUES (gen_random_uuid(), gen_random_uuid(), $1, $2, $3)`
	grantedAt := time.Date(2026, time.October, 1, 9, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		level, priority, grantedAt any
		state                      string
	}{
		"application link":     {nil, nil, nil, ""},
		"personal link":        {"group", 0, grantedAt, ""},
		"missing granted_at":   {"group", 1, nil, "23514"},
		"missing level":        {nil, 1, grantedAt, "23514"},
		"unknown level":        {"team", 1, grantedAt, "23514"},
		"negative priority":    {"user", -1, grantedAt, "23514"},
		"missing priority":     {"all", nil, grantedAt, "23514"},
		"level without others": {"user", nil, nil, "23514"},
		"infinite granted_at":  {"group", 1, "infinity", "23514"},
	} {
		require.Equal(t, tc.state, sqlStateOf(t, ctx, tx, insert, tc.level, tc.priority, tc.grantedAt), name)
	}

	runTwice(t, ctx, tx, downAddConsumerAuthGrant)
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'consumer_auth'::regclass AND attname IN ('level', 'priority', 'granted_at') AND NOT attisdropped`))
	require.Equal(t, 2, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumer_auth`))
}
