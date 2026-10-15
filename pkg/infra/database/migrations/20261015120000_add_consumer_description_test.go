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

func TestAddConsumerDescriptionMigration(t *testing.T) {
	const gatewayG = "aaaaaaaa-0000-0000-0000-00000000000c"
	const descriptionColumn = `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'consumers'::regclass AND attname = 'description' AND NOT attisdropped`
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE consumers (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), gateway_id UUID NOT NULL, name TEXT NOT NULL) ON COMMIT DROP;
		INSERT INTO consumers (gateway_id, name) VALUES ('`+gatewayG+`', 'billing'), ('`+gatewayG+`', 'support')`)

	runTwice(t, ctx, tx, upAddConsumerDescription)
	require.Equal(t, 1, countOf(t, ctx, tx, `SELECT COUNT(*) FROM pg_attribute WHERE attrelid = 'consumers'::regclass AND attname = 'description' AND atttypid = 'text'::regtype AND attnotnull`))
	require.Equal(t, 2, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumers WHERE description = ''`), "existing consumers get an empty description")

	runTwice(t, ctx, tx, downAddConsumerDescription)
	require.Zero(t, countOf(t, ctx, tx, descriptionColumn))
	require.Equal(t, 2, countOf(t, ctx, tx, `SELECT COUNT(*) FROM consumers`), "the down migration keeps every consumer")
}
