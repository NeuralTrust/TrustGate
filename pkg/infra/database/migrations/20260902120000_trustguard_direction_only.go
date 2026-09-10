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

// TrustGuard policies could carry two settings keys for one axis: "direction",
// declared by the policy catalog and edited by the console form, and "inspect",
// an older name for the same thing. Nothing removed the second, and the plugin
// resolved it ahead of the first — so a policy edited to
// direction=request_response while a stale inspect=request remained inspected
// the request leg only. The console still showed "Request & Response", the guard
// was never called on responses, and because the form re-sent the stale value on
// every save it could not be cleared from the UI.
//
// The plugin now reads "direction" and nothing else, which makes this migration
// load-bearing rather than cosmetic: a policy storing only "inspect" would
// otherwise fall back to the default on the first request after deploy. Collapse
// the pair the way the plugin used to resolve a lone legacy key — carry its
// value into "direction" when "direction" has none — and drop it.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260902120000_trustguard_direction_only",
		Name: "collapse trustguard policy inspect setting into direction",
		Up:   upTrustGuardDirectionOnly,
		Down: downTrustGuardDirectionOnly,
	})
}

func upTrustGuardDirectionOnly(ctx context.Context, tx pgx.Tx) error {
	// NULLIF guards a key that is present but empty: that decodes to the plugin
	// default, not to an empty direction, so it must not win the COALESCE.
	const stmt = `
		UPDATE policies
		   SET settings = (settings - 'inspect')
		                  || jsonb_build_object(
		                       'direction',
		                       COALESCE(
		                         NULLIF(settings->>'direction', ''),
		                         NULLIF(settings->>'inspect', ''),
		                         'request_response'
		                       )
		                     )
		 WHERE slug = 'trustguard'
		   AND settings ? 'inspect';`
	_, err := tx.Exec(ctx, stmt)
	return err
}

// downTrustGuardDirectionOnly restores the legacy key alongside the canonical
// one, set to the same value, so a rolled-back binary — which reads "inspect"
// first — selects the same legs. It cannot recover an "inspect" that disagreed
// with "direction": that value is exactly what Up dropped, and reinstating it
// would reintroduce the defect.
func downTrustGuardDirectionOnly(ctx context.Context, tx pgx.Tx) error {
	const stmt = `
		UPDATE policies
		   SET settings = settings
		                  || jsonb_build_object(
		                       'inspect',
		                       COALESCE(NULLIF(settings->>'direction', ''), 'request_response')
		                     )
		 WHERE slug = 'trustguard'
		   AND NOT settings ? 'inspect';`
	_, err := tx.Exec(ctx, stmt)
	return err
}
