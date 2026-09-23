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

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/google/uuid"
)

// backfillPageSize bounds how many policy rows BackfillCredentialEncryption
// reads per round trip, so a large policies table is walked in bounded
// batches instead of one unbounded SELECT.
const backfillPageSize = 200

// BackfillCredentialEncryption converges every existing policy row's
// declared credential leaves (appplugins.CredentialSettings) to encrypted,
// for rows written before RUN-1646 introduced leaf-level encryption in
// marshalSettings.
//
// This cannot be a database migration: migrations run with only a pgx.Tx
// (see pkg/infra/database/migrations) and have no cipher, and the cipher's
// secret is only assembled at application boot (see
// pkg/container/modules/core.go, which may resolve a shared secret over
// Redis in production). It instead runs once at boot on the plane that owns
// policy writes (see cmd/trustgate/main.go, alongside StartCatalogSync).
//
// It is safe to run repeatedly and concurrently with live traffic:
//
//   - secret.EncryptSettings is a no-op on a leaf that already carries
//     secret.EncVersionPrefix, so two overlapping passes (two pods booting
//     together, or a restart) never double-encrypt a leaf.
//   - each row is rewritten with a compare-and-swap
//     (`UPDATE ... WHERE id = $1 AND settings = $2::jsonb`) against the exact
//     bytes this pass read. A concurrent policy Update (which now always
//     encrypts through marshalSettings) or another backfill pass touching the
//     same row between this pass's read and write makes the CAS affect zero
//     rows instead of clobbering the newer write; the row is simply left for
//     whichever pass runs next, and it is already correct regardless.
//   - a row whose settings fail to unmarshal, or whose slug has no
//     registered plugin, is skipped rather than aborting the whole backfill —
//     one bad or orphaned row must not block every other row from being
//     encrypted, mirroring why the tolerant read in scanPolicy exists.
//
// It returns the number of rows it actually rewrote.
func (r *Repository) BackfillCredentialEncryption(ctx context.Context) (int, error) {
	if r.cipher == nil || r.registry == nil {
		return 0, nil
	}

	type row struct {
		id       uuid.UUID
		slug     string
		settings []byte
	}

	updated := 0
	var afterID uuid.UUID
	for {
		rows, err := r.conn.Pool.Query(ctx,
			`SELECT id, slug, settings FROM policies WHERE id > $1 ORDER BY id LIMIT $2`,
			afterID, backfillPageSize,
		)
		if err != nil {
			return updated, fmt.Errorf("policy repository: backfill query: %w", err)
		}
		batch := make([]row, 0, backfillPageSize)
		for rows.Next() {
			var rr row
			if err := rows.Scan(&rr.id, &rr.slug, &rr.settings); err != nil {
				rows.Close()
				return updated, fmt.Errorf("policy repository: backfill scan: %w", err)
			}
			batch = append(batch, rr)
		}
		iterErr := rows.Err()
		rows.Close()
		if iterErr != nil {
			return updated, fmt.Errorf("policy repository: backfill iter: %w", iterErr)
		}
		if len(batch) == 0 {
			return updated, nil
		}

		for _, rr := range batch {
			afterID = rr.id
			if ctx.Err() != nil {
				return updated, ctx.Err()
			}

			paths := appplugins.PluginCredentialPaths(r.registry, rr.slug)
			if len(paths) == 0 || len(rr.settings) == 0 {
				continue
			}
			var settings map[string]any
			if err := json.Unmarshal(rr.settings, &settings); err != nil {
				// A row that predates valid JSON settings is not this
				// backfill's job to repair; leave it for a human.
				continue
			}
			encrypted, err := secret.EncryptSettings(settings, paths, r.cipher)
			if err != nil {
				// One row's encryption failure (e.g. a cipher error) must not
				// stop every other row from being encrypted.
				continue
			}
			// EncryptSettings (via TransformSettings) returns the very same
			// map, by reference, when no declared leaf needed encrypting —
			// the same contract MaskSettings already guarantees (see
			// pkg/common/secret's TestMaskSettings_ReturnsSameMapWhenNothingToMask).
			// Comparing pointers here, rather than re-marshalling and
			// comparing bytes against rr.settings, sidesteps a real
			// formatting mismatch: Postgres's jsonb text output
			// (`{"a": "b"}`, spaced) never byte-equals Go's compact
			// json.Marshal (`{"a":"b"}`), which would make every row look
			// "changed" on every pass and break idempotency.
			if reflect.ValueOf(settings).Pointer() == reflect.ValueOf(encrypted).Pointer() {
				continue // already converged; nothing to write
			}
			newBytes, err := json.Marshal(encrypted)
			if err != nil {
				continue
			}

			cmd, err := r.conn.Pool.Exec(ctx,
				`UPDATE policies SET settings = $1::jsonb WHERE id = $2 AND settings = $3::jsonb`,
				newBytes, rr.id, rr.settings,
			)
			if err != nil {
				return updated, fmt.Errorf("policy repository: backfill update %s: %w", rr.id, err)
			}
			updated += int(cmd.RowsAffected())
		}

		if len(batch) < backfillPageSize {
			return updated, nil
		}
	}
}
