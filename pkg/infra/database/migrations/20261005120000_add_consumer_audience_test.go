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

func TestAddConsumerAudienceMigration(t *testing.T) {
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE consumers (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), type TEXT NOT NULL) ON COMMIT DROP;
		INSERT INTO consumers (type) VALUES ('LLM'), ('MCP'), ('A2A')`)

	runTwice(t, ctx, tx, upAddConsumerAudience)
	require.Equal(t, 3, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumers WHERE audience = 'application'`))
	const insert = `INSERT INTO consumers (type, audience) VALUES ('LLM', $1)`
	require.Equal(t, "23514", sqlStateOf(t, ctx, tx, insert, "team"))
	require.Empty(t, sqlStateOf(t, ctx, tx, insert, "personal"))

	runTwice(t, ctx, tx, downAddConsumerAudience)
	require.Zero(t, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'consumers'::regclass AND attname = 'audience' AND NOT attisdropped`))
}
