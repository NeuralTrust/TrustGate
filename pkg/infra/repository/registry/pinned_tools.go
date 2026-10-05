// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package registry

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

var _ domain.PinnedToolRepository = (*PinnedToolRepository)(nil)

// PinnedToolRepository stores the tool decisions of pinned registries in
// registry_tools. The table carries no gateway_id of its own: every query joins
// registries and filters on its gateway_id, the same ownership check the
// registry repository applies, so a registry id from another gateway matches
// nothing. It does not append a config-snapshot marker: the decisions are not
// part of the snapshot.
type PinnedToolRepository struct {
	conn *database.Connection
}

func NewPinnedToolRepository(conn *database.Connection) *PinnedToolRepository {
	return &PinnedToolRepository{conn: conn}
}

func (r *PinnedToolRepository) ListByRegistry(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) ([]domain.PinnedTool, error) {
	const query = `
		SELECT t.registry_id, t.tool_name, t.fingerprint, t.definition, t.status, t.first_seen_at, t.decided_at, t.decided_by
		  FROM registry_tools t
		  JOIN registries r ON r.id = t.registry_id
		 WHERE t.registry_id = $1
		   AND r.gateway_id = $2
		 ORDER BY t.tool_name, t.first_seen_at, t.fingerprint`
	rows, err := r.conn.Pool.Query(ctx, query, registryID, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("pinned tool repository: list: %w", err)
	}
	defer rows.Close()

	var out []domain.PinnedTool
	for rows.Next() {
		var (
			t         domain.PinnedTool
			status    string
			decidedAt *time.Time
			decidedBy *string
		)
		if err := rows.Scan(&t.RegistryID, &t.Name, &t.Fingerprint, &t.Definition, &status, &t.FirstSeenAt, &decidedAt, &decidedBy); err != nil {
			return nil, fmt.Errorf("pinned tool repository: scan: %w", err)
		}
		t.Status = domain.ToolStatus(status)
		if decidedAt != nil {
			t.DecidedAt = *decidedAt
		}
		if decidedBy != nil {
			t.DecidedBy = *decidedBy
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pinned tool repository: iter: %w", err)
	}
	return out, nil
}

func (r *PinnedToolRepository) UpsertPending(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	tools []domain.ToolCandidate,
) (int, error) {
	names, fingerprints, definitions := splitCandidates(tools)
	if len(names) == 0 {
		return 0, nil
	}
	// DO NOTHING is what keeps an approved or rejected row's status: a tool the
	// admin already decided on is never pushed back to pending by a re-discovery.
	const query = `
		INSERT INTO registry_tools (registry_id, tool_name, fingerprint, definition, status)
		SELECT r.id, x.name, x.fp, x.def::jsonb, 'pending'
		  FROM registries r, unnest($3::text[], $4::text[], $5::text[]) AS x(name, fp, def)
		 WHERE r.id = $1
		   AND r.gateway_id = $2
		ON CONFLICT (registry_id, tool_name, fingerprint) DO NOTHING`
	cmd, err := r.conn.Pool.Exec(ctx, query, registryID, gatewayID, names, fingerprints, definitions)
	if err != nil {
		return 0, fmt.Errorf("pinned tool repository: upsert pending: %w", err)
	}
	return int(cmd.RowsAffected()), nil
}

func (r *PinnedToolRepository) SetStatus(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	refs []domain.ToolRef,
	status domain.ToolStatus,
	decidedBy string,
) (int, error) {
	if !status.IsValid() {
		return 0, fmt.Errorf("pinned tool repository: invalid status %q", status)
	}
	names, fingerprints := splitRefs(refs)
	if len(names) == 0 {
		return 0, nil
	}
	// Going back to pending clears the decision; any other status stamps it.
	const query = `
		UPDATE registry_tools t
		   SET status     = $3,
		       decided_at = CASE WHEN $3 = 'pending' THEN NULL ELSE now() END,
		       decided_by = CASE WHEN $3 = 'pending' THEN NULL ELSE NULLIF($4, '') END
		  FROM unnest($5::text[], $6::text[]) AS x(name, fp),
		       registries r
		 WHERE t.registry_id = $1
		   AND r.id = t.registry_id
		   AND r.gateway_id = $2
		   AND t.tool_name = x.name
		   AND t.fingerprint = x.fp`
	cmd, err := r.conn.Pool.Exec(ctx, query, registryID, gatewayID, string(status), decidedBy, names, fingerprints)
	if err != nil {
		return 0, fmt.Errorf("pinned tool repository: set status: %w", err)
	}
	return int(cmd.RowsAffected()), nil
}

func (r *PinnedToolRepository) ApproveAll(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	tools []domain.ToolCandidate,
	decidedBy string,
) error {
	names, fingerprints, definitions := splitCandidates(tools)
	const lock = `SELECT 1 FROM registries WHERE id = $1 AND gateway_id = $2 FOR SHARE`
	// Unlike UpsertPending this overwrites: approving is an explicit admin act
	// and wins over a stored pending or rejected decision for the same ref.
	const upsert = `
		INSERT INTO registry_tools (registry_id, tool_name, fingerprint, definition, status, decided_at, decided_by)
		SELECT $1::uuid, x.name, x.fp, x.def::jsonb, 'approved', now(), NULLIF($2::text, '')
		  FROM unnest($3::text[], $4::text[], $5::text[]) AS x(name, fp, def)
		ON CONFLICT (registry_id, tool_name, fingerprint) DO UPDATE
		   SET status     = 'approved',
		       decided_at = now(),
		       decided_by = NULLIF($2::text, '')`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		var one int
		if err := tx.QueryRow(ctx, lock, registryID, gatewayID).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrNotFound
			}
			return fmt.Errorf("pinned tool repository: lock registry: %w", err)
		}
		if len(names) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, upsert, registryID, decidedBy, names, fingerprints, definitions); err != nil {
			return fmt.Errorf("pinned tool repository: approve all: %w", err)
		}
		return nil
	})
}

// splitRefs flattens refs into the two parallel arrays unnest zips back into
// rows, dropping duplicates: ON CONFLICT DO UPDATE refuses a statement that
// proposes the same key twice.
func splitRefs(refs []domain.ToolRef) (names, fingerprints []string) {
	seen := make(map[domain.ToolRef]struct{}, len(refs))
	names = make([]string, 0, len(refs))
	fingerprints = make([]string, 0, len(refs))
	for _, ref := range refs {
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		names = append(names, ref.Name)
		fingerprints = append(fingerprints, ref.Fingerprint)
	}
	return names, fingerprints
}

// splitCandidates is splitRefs for candidates: the same de-duplication by
// (name, fingerprint), plus the definitions as text for the jsonb cast. The
// first definition of a duplicated ref wins; equal fingerprints mean equal
// canonical definitions.
//
// The result is sorted by (name, fingerprint). Two concurrent ApproveAll calls
// with overlapping tools lock the rows they upsert in statement order; one
// fixed order makes that a wait instead of a 40P01 deadlock.
func splitCandidates(tools []domain.ToolCandidate) (names, fingerprints, definitions []string) {
	sorted := slices.Clone(tools)
	slices.SortFunc(sorted, func(a, b domain.ToolCandidate) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	seen := make(map[domain.ToolRef]struct{}, len(sorted))
	for _, tool := range sorted {
		if _, dup := seen[tool.ToolRef]; dup {
			continue
		}
		seen[tool.ToolRef] = struct{}{}
		names = append(names, tool.Name)
		fingerprints = append(fingerprints, tool.Fingerprint)
		definitions = append(definitions, string(tool.Definition))
	}
	return names, fingerprints, definitions
}
