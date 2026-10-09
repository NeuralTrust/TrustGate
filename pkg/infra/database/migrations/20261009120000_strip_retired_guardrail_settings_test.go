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
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const staleGuardrailSettings = `{
	"keep": "v",
	"ON_ERROR": "fail_closed", "On_Timeout": "fail_closed", "timeout": "5m", "on_mask_failure": "block",
	"Streaming": {"enabled": true, "On_Error": "fail_closed", "GUARD_TIMEOUT": "1ms"}
}`

func settingsOf(t *testing.T, ctx context.Context, tx pgx.Tx, id string) map[string]any {
	t.Helper()
	var raw []byte
	require.NoError(t, tx.QueryRow(ctx, `SELECT settings FROM policies WHERE id = $1`, id).Scan(&raw))
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestStripRetiredGuardrailSettingsMigration(t *testing.T) {
	ctx, tx := beginShadowTx(t, `
		CREATE TEMP TABLE policies (id TEXT PRIMARY KEY, slug TEXT NOT NULL, settings JSONB NOT NULL DEFAULT '{}'::jsonb) ON COMMIT DROP;
		INSERT INTO policies (id, slug, settings) VALUES
			('trustguard', 'trustguard', '`+staleGuardrailSettings+`'),
			('bedrock', 'bedrock_guardrail', '`+staleGuardrailSettings+`'),
			('armor', 'google_model_armor', '`+staleGuardrailSettings+`'),
			('openai', 'openai_moderation', '`+staleGuardrailSettings+`'),
			('azure', 'azure_content_safety', '`+staleGuardrailSettings+`'),
			('regex', 'regex_replace', '{"on_mask_failure": "block", "streaming": {"on_error": "fail_closed", "enabled": true, "GUARD_TIMEOUT": "1ms"}}'),
			('other', 'rate_limiter', '`+staleGuardrailSettings+`'),
			('clean', 'trustguard', '{"collector_id": "c", "streaming": {"enabled": false}}'),
			('only-stale', 'bedrock_guardrail', '{"on_error": "fail_closed"}'),
			('no-stream-object', 'trustguard', '{"streaming": "x", "on_error": "fail_closed"}')`)

	runTwice(t, ctx, tx, upStripRetiredGuardrailSettings)

	streamingOnly := map[string]any{"enabled": true}
	require.Equal(t, map[string]any{"keep": "v", "Streaming": streamingOnly}, settingsOf(t, ctx, tx, "trustguard"),
		"trustguard loses its failure keys, the timeout and the stream failure policy at any case")
	require.Equal(t, map[string]any{"keep": "v", "timeout": "5m", "On_Timeout": "fail_closed", "Streaming": streamingOnly}, settingsOf(t, ctx, tx, "bedrock"))
	require.Equal(t, map[string]any{"keep": "v", "timeout": "5m", "On_Timeout": "fail_closed", "Streaming": streamingOnly}, settingsOf(t, ctx, tx, "armor"))
	require.Equal(t, map[string]any{"keep": "v", "timeout": "5m", "On_Timeout": "fail_closed", "on_mask_failure": "block", "Streaming": streamingOnly}, settingsOf(t, ctx, tx, "openai"))
	require.Equal(t, map[string]any{
		"keep": "v", "timeout": "5m", "On_Timeout": "fail_closed", "on_mask_failure": "block",
		"Streaming": map[string]any{"enabled": true, "On_Error": "fail_closed", "GUARD_TIMEOUT": "1ms"},
	}, settingsOf(t, ctx, tx, "azure"), "azure_content_safety retires on_error only")
	require.Equal(t, map[string]any{"streaming": map[string]any{"on_error": "fail_closed", "enabled": true}}, settingsOf(t, ctx, tx, "regex"),
		"regex_replace keeps its fail-closed stream policy and loses its guard timeout")
	var other map[string]any
	require.NoError(t, json.Unmarshal([]byte(staleGuardrailSettings), &other))
	require.Equal(t, other, settingsOf(t, ctx, tx, "other"), "a plugin outside the list is untouched")
	require.Equal(t, map[string]any{"collector_id": "c", "streaming": map[string]any{"enabled": false}}, settingsOf(t, ctx, tx, "clean"))
	require.Equal(t, map[string]any{}, settingsOf(t, ctx, tx, "only-stale"), "a row left with nothing is an empty object, not NULL")
	require.Equal(t, map[string]any{"streaming": "x"}, settingsOf(t, ctx, tx, "no-stream-object"), "a streaming value that is not an object is left alone")

	runTwice(t, ctx, tx, downStripRetiredGuardrailSettings)
	require.Equal(t, map[string]any{"keep": "v", "Streaming": streamingOnly}, settingsOf(t, ctx, tx, "trustguard"), "down is a no-op")
}
