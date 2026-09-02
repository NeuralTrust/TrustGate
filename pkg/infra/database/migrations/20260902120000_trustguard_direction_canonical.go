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

// TrustGuard policies could carry two settings keys for the same axis:
// "direction", which the policy catalog declares and the console form edits, and
// "inspect", the plugin's older name for it. Nothing ever removed the second, so
// a policy edited through the console ended up holding both — and while the old
// precedence let "inspect" win, the value the operator could not see decided
// which legs ran. That silently disabled response-leg inspection on at least one
// production policy.
//
// The plugin now reads "direction" and only falls back to "inspect" when
// "direction" is unset, so this migration collapses the stored pair the same way:
// keep the effective value under "direction" and drop the legacy key. Rows that
// never carried "inspect" are untouched.
func init() {
	database.RegisterMigration(database.Migration{
		ID:   "20260902120000_trustguard_direction_canonical",
		Name: "collapse trustguard policy inspect setting into direction",
		Up:   upTrustGuardDirectionCanonical,
		Down: downTrustGuardDirectionCanonical,
	})
}

func upTrustGuardDirectionCanonical(ctx context.Context, tx pgx.Tx) error {
	// COALESCE mirrors parseConfig: "direction" when it holds a value, the legacy
	// "inspect" otherwise. NULLIF guards a key present but empty, which decodes to
	// the default rather than to an empty direction.
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

// downTrustGuardDirectionCanonical restores the legacy key alongside the
// canonical one, set to the same value. It cannot recover a divergent "inspect"
// — that value is exactly what the Up dropped — but writing the effective
// direction back into it leaves the pre-migration binary reading the same legs,
// which is what a rollback has to preserve.
func downTrustGuardDirectionCanonical(ctx context.Context, tx pgx.Tx) error {
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
