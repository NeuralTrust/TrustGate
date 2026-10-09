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

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

// What a guardrail does when it fails is decided by the failure's class and the
// policy's mode, not by a stored setting: the plugins ignore on_error,
// on_timeout, the per-policy timeout, on_mask_failure and streaming.on_error /
// streaming.guard_timeout. A row that still stores one reads back through
// GET /policies and the Terraform provider as a behaviour the gateway does not
// have (a policy showing "fail closed" that fails open on an availability
// failure), and a binary of another release that still decodes the key would act
// on it. Drop them from the rows that carry them.
//
// Per slug, the keys dropped are the ones that plugin's RetiredSettings declares:
//
//	trustguard            on_error, on_timeout, timeout, on_mask_failure,
//	                      streaming.on_error, streaming.guard_timeout
//	bedrock_guardrail     on_error, on_mask_failure, streaming.on_error, streaming.guard_timeout
//	google_model_armor    on_error, on_mask_failure, streaming.on_error, streaming.guard_timeout
//	openai_moderation     on_error, streaming.on_error, streaming.guard_timeout
//	azure_content_safety  on_error
//	regex_replace         on_mask_failure (its streaming.on_error stays: it is a rewriter)
//
// Slugs are the plugin names; no alias is stored as a slug. Keys are matched on
// lower(key) because settings are decoded with mapstructure, which matches key
// names case-insensitively: "ON_ERROR" is as live as "on_error". Only the top
// level and the "streaming" object are walked, which is every place those keys
// live.
//
// Running this while pods of the previous release are still serving is safe
// because the previous release defaults every one of these keys to the
// fail-open, deployment-wide behaviour when it is absent: on_error, on_timeout
// and streaming.on_error default to fail_open (streaming.on_error inherits
// on_error, itself fail_open), on_mask_failure defaults to pass, and an empty
// timeout / streaming.guard_timeout means TRUSTGUARD_TIMEOUT and the plugin's
// default guard timeout. A row the migration rewrites therefore behaves, on
// either release, as it did with the default values. The one row whose behaviour
// changes on the old release is one that stored a non-default value, which is the
// point: its stored fail_closed is what the new release never honours.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20261009120000_strip_retired_guardrail_settings",
		Name: "strip the retired fail-open settings from guardrail policies",
		Up:   upStripRetiredGuardrailSettings,
		Down: downStripRetiredGuardrailSettings,
	})
}

func upStripRetiredGuardrailSettings(ctx context.Context, tx pgx.Tx) error {
	// A row with nothing to strip is not rewritten, which keeps the statement
	// idempotent and leaves updated rows limited to the ones that change.
	const stmt = `
		WITH retired (slug, top_keys, stream_keys) AS (
			VALUES
				('trustguard',
				 ARRAY['on_error', 'on_timeout', 'timeout', 'on_mask_failure'],
				 ARRAY['on_error', 'guard_timeout']),
				('bedrock_guardrail',
				 ARRAY['on_error', 'on_mask_failure'],
				 ARRAY['on_error', 'guard_timeout']),
				('google_model_armor',
				 ARRAY['on_error', 'on_mask_failure'],
				 ARRAY['on_error', 'guard_timeout']),
				('openai_moderation',
				 ARRAY['on_error'],
				 ARRAY['on_error', 'guard_timeout']),
				('azure_content_safety',
				 ARRAY['on_error'],
				 ARRAY[]::text[]),
				('regex_replace',
				 ARRAY['on_mask_failure'],
				 ARRAY[]::text[])
		)
		UPDATE policies p
		   SET settings = (
		         SELECT COALESCE(
		                  jsonb_object_agg(
		                    e.key,
		                    CASE
		                      WHEN lower(e.key) = 'streaming' AND jsonb_typeof(e.value) = 'object'
		                      THEN (
		                        SELECT COALESCE(jsonb_object_agg(s.key, s.value), '{}'::jsonb)
		                          FROM jsonb_each(e.value) AS s
		                         WHERE lower(s.key) <> ALL (r.stream_keys)
		                      )
		                      ELSE e.value
		                    END
		                  ),
		                  '{}'::jsonb
		                )
		           FROM jsonb_each(p.settings) AS e
		          WHERE lower(e.key) <> ALL (r.top_keys)
		       )
		  FROM retired r
		 WHERE p.slug = r.slug
		   AND jsonb_typeof(p.settings) = 'object'
		   AND EXISTS (
		         SELECT 1
		           FROM jsonb_each(p.settings) AS e
		          WHERE lower(e.key) = ANY (r.top_keys)
		             OR (
		                  lower(e.key) = 'streaming'
		              AND jsonb_typeof(e.value) = 'object'
		              AND EXISTS (
		                    SELECT 1
		                      FROM jsonb_object_keys(e.value) AS k
		                     WHERE lower(k) = ANY (r.stream_keys)
		                  )
		                )
		       );`
	_, err := tx.Exec(ctx, stmt)
	return err
}

// downStripRetiredGuardrailSettings is a deliberate no-op. Up drops values the
// new release never honours, so a rollback cannot give them back: a policy that
// stored fail_closed loses it and runs with the old release's defaults, which is
// the intended product behaviour. Reinstating a fail_closed or a 1ms timeout
// would only recreate the mismatch between what a policy shows and what the
// gateway does.
func downStripRetiredGuardrailSettings(_ context.Context, _ pgx.Tx) error {
	return nil
}
