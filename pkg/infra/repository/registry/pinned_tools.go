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
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5"
)

var _ domain.PinnedToolRepository = (*PinnedToolRepository)(nil)

// PinnedToolRepository stores the tool decisions of pinned registries in
// registry_tools. The table carries no gateway_id of its own: every query joins
// registries and filters on its gateway_id, the same ownership check the
// registry repository applies, so a registry id from another gateway matches
// nothing.
//
// A write that changes a decision runs in one transaction with a bump of the
// registry (updated_at plus a config-snapshot change marker, the same marker a
// registry update appends), because the decisions are part of the compiled
// snapshot. UpsertPending does not bump: pending rows are not in the snapshot.
type PinnedToolRepository struct {
	conn   *database.Connection
	outbox outbox.Appender
}

func NewPinnedToolRepository(conn *database.Connection, appender outbox.Appender) *PinnedToolRepository {
	return &PinnedToolRepository{conn: conn, outbox: appender}
}

// withBump runs fn in a transaction that holds the registry row with
// FOR NO KEY UPDATE (it queues other writers of the same registry, including
// recorders, and does not block the foreign-key lock of an insert), and when fn reports a change bumps the registry's updated_at
// and appends the snapshot marker before committing. kind is the registry type,
// for fn to check. A registry that is not the gateway's is ErrNotFound.
func (r *PinnedToolRepository) withBump(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	fn func(tx pgx.Tx, kind string) (changed bool, err error),
) error {
	const lock = `SELECT type FROM registries WHERE id = $1 AND gateway_id = $2 FOR NO KEY UPDATE`
	const bump = `UPDATE registries SET updated_at = now() WHERE id = $1 AND gateway_id = $2`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		var kind string
		if err := tx.QueryRow(ctx, lock, registryID, gatewayID).Scan(&kind); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrNotFound
			}
			return fmt.Errorf("pinned tool repository: lock registry: %w", err)
		}
		changed, err := fn(tx, kind)
		if err != nil || !changed {
			return err
		}
		if _, err := tx.Exec(ctx, bump, registryID, gatewayID); err != nil {
			return fmt.Errorf("pinned tool repository: bump registry: %w", err)
		}
		return r.outbox.AppendTx(ctx, tx)
	})
}

func (r *PinnedToolRepository) ListPage(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	status *domain.ToolStatus,
	limit, offset int,
) ([]domain.PinnedTool, int, error) {
	var filter *string
	if status != nil {
		s := string(*status)
		filter = &s
	}
	const count = `
		SELECT count(*)
		  FROM registry_tools t JOIN registries r ON r.id = t.registry_id
		 WHERE t.registry_id = $1 AND r.gateway_id = $2 AND ($3::text IS NULL OR t.status = $3)`
	var total int
	if err := r.conn.Pool.QueryRow(ctx, count, registryID, gatewayID, filter).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("pinned tool repository: count: %w", err)
	}
	const query = `
		SELECT t.registry_id, t.tool_name, t.fingerprint, t.definition, t.status, t.first_seen_at, t.decided_at, t.decided_by
		  FROM registry_tools t
		  JOIN registries r ON r.id = t.registry_id
		 WHERE t.registry_id = $1 AND r.gateway_id = $2 AND ($3::text IS NULL OR t.status = $3)
		 ORDER BY t.first_seen_at, t.tool_name, t.fingerprint
		 LIMIT $4 OFFSET $5`
	items, err := r.scanTools(ctx, query, registryID, gatewayID, filter, limit, offset)
	return items, total, err
}

func (r *PinnedToolRepository) ListApproved(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	names []string,
) ([]domain.PinnedTool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	const query = `
		SELECT t.registry_id, t.tool_name, t.fingerprint, t.definition, t.status, t.first_seen_at, t.decided_at, t.decided_by
		  FROM registry_tools t
		  JOIN registries r ON r.id = t.registry_id
		 WHERE t.registry_id = $1 AND r.gateway_id = $2 AND t.status = 'approved' AND t.tool_name = ANY($3::text[])
		 ORDER BY t.tool_name, t.fingerprint`
	return r.scanTools(ctx, query, registryID, gatewayID, names)
}

func (r *PinnedToolRepository) scanTools(ctx context.Context, query string, args ...any) ([]domain.PinnedTool, error) {
	rows, err := r.conn.Pool.Query(ctx, query, args...)
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

// UpsertPending inserts the missing definitions as pending while the registry
// stays under MaxPendingPerRegistry and each tool name under
// MaxPendingPerToolName pending rows.
//
// The caps are race-free because the whole check-and-insert runs in one
// transaction that first takes the registry row FOR NO KEY UPDATE. That lock
// conflicts with itself, so concurrent recorders of the same registry (other
// pods, the RPC) queue up and each counts what the previous one committed. FOR
// KEY SHARE would not do: shared holders do not exclude each other, so two
// callers could both read "499" and both insert. NO KEY UPDATE still does not
// conflict with the foreign-key lock an insert into registry_tools takes on
// other registries, and a recorder only waits for another writer of the same
// registry (a decision or another recorder), which is short.
func (r *PinnedToolRepository) UpsertPending(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	tools []domain.ToolCandidate,
) (inserted, dropped int, err error) {
	names, fingerprints, definitions := splitCandidates(tools)
	if len(names) == 0 {
		return 0, 0, nil
	}
	err = r.withBump(ctx, gatewayID, registryID, func(tx pgx.Tx, _ string) (bool, error) {
		var err error
		inserted, dropped, err = insertPendingCapped(ctx, tx, registryID, names, fingerprints, definitions)
		return false, err // pending rows are not in the snapshot: no bump
	})
	if errors.Is(err, domain.ErrNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("pinned tool repository: upsert pending: %w", err)
	}
	return inserted, dropped, nil
}

func insertPendingCapped(
	ctx context.Context,
	tx pgx.Tx,
	registryID ids.RegistryID,
	names, fingerprints, definitions []string,
) (inserted, dropped int, err error) {
	// DO NOTHING semantics: a stored row, whatever its status, is never touched
	// and never counted against the caps again.
	stored := map[domain.ToolRef]struct{}{}
	pendingByName := map[string]int{}
	var pendingTotal int
	rows, err := tx.Query(ctx,
		`SELECT tool_name, fingerprint, status FROM registry_tools WHERE registry_id = $1`, registryID)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var name, fp, status string
		if err := rows.Scan(&name, &fp, &status); err != nil {
			rows.Close()
			return 0, 0, err
		}
		stored[domain.ToolRef{Name: name, Fingerprint: fp}] = struct{}{}
		if domain.ToolStatus(status) == domain.ToolStatusPending {
			pendingTotal++
			pendingByName[name]++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	var inNames, inFPs, inDefs []string
	for i := range names {
		if _, ok := stored[domain.ToolRef{Name: names[i], Fingerprint: fingerprints[i]}]; ok {
			continue
		}
		if pendingTotal >= domain.MaxPendingPerRegistry || pendingByName[names[i]] >= domain.MaxPendingPerToolName {
			dropped++
			continue
		}
		pendingTotal++
		pendingByName[names[i]]++
		inNames, inFPs, inDefs = append(inNames, names[i]), append(inFPs, fingerprints[i]), append(inDefs, definitions[i])
	}
	if len(inNames) == 0 {
		return 0, dropped, nil
	}
	const query = `
		INSERT INTO registry_tools (registry_id, tool_name, fingerprint, definition, status)
		SELECT $1::uuid, x.name, x.fp, x.def::jsonb, 'pending'
		  FROM unnest($2::text[], $3::text[], $4::text[]) AS x(name, fp, def)
		ON CONFLICT (registry_id, tool_name, fingerprint) DO NOTHING`
	cmd, err := tx.Exec(ctx, query, registryID, inNames, inFPs, inDefs)
	if err != nil {
		return 0, 0, err
	}
	return int(cmd.RowsAffected()), dropped, nil
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
	var n int
	err := r.withBump(ctx, gatewayID, registryID, func(tx pgx.Tx, _ string) (bool, error) {
		var err error
		n, err = setStatusTx(ctx, tx, registryID, refs, status, decidedBy)
		return n > 0, err
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (r *PinnedToolRepository) Decide(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	approve, reject []domain.ToolRef,
	decidedBy string,
) error {
	return r.withBump(ctx, gatewayID, registryID, func(tx pgx.Tx, _ string) (bool, error) {
		if err := requireStored(ctx, tx, registryID, approve, reject); err != nil {
			return false, err
		}
		a, err := setStatusTx(ctx, tx, registryID, approve, domain.ToolStatusApproved, decidedBy)
		if err != nil {
			return false, err
		}
		b, err := setStatusTx(ctx, tx, registryID, reject, domain.ToolStatusRejected, decidedBy)
		if err != nil {
			return false, err
		}
		return a+b > 0, nil
	})
}

// requireStored fails with ErrUnknownToolRefs, naming up to maxNamedUnknown
// refs, when any ref has no row for the registry. The registry row is already
// locked, so a concurrent approve cannot slip between this check and the writes.
func requireStored(ctx context.Context, tx pgx.Tx, registryID ids.RegistryID, groups ...[]domain.ToolRef) error {
	var all []domain.ToolRef
	for _, g := range groups {
		all = append(all, g...)
	}
	names, fingerprints := splitRefs(all)
	if len(names) == 0 {
		return nil
	}
	const query = `
		SELECT x.name
		  FROM unnest($2::text[], $3::text[]) AS x(name, fp)
		 WHERE NOT EXISTS (
		       SELECT 1 FROM registry_tools t
		        WHERE t.registry_id = $1 AND t.tool_name = x.name AND t.fingerprint = x.fp)`
	rows, err := tx.Query(ctx, query, registryID, names, fingerprints)
	if err != nil {
		return fmt.Errorf("pinned tool repository: check refs: %w", err)
	}
	defer rows.Close()
	var missing []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("pinned tool repository: scan refs: %w", err)
		}
		missing = append(missing, name)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("pinned tool repository: check refs: %w", err)
	}
	if len(missing) == 0 {
		return nil
	}
	const maxNamedUnknown = 10
	listed := missing
	if len(listed) > maxNamedUnknown {
		listed = listed[:maxNamedUnknown]
	}
	return fmt.Errorf("%w: %d not found for this registry (%q)", domain.ErrUnknownToolRefs, len(missing), listed)
}

func setStatusTx(
	ctx context.Context,
	tx pgx.Tx,
	registryID ids.RegistryID,
	refs []domain.ToolRef,
	status domain.ToolStatus,
	decidedBy string,
) (int, error) {
	names, fingerprints := splitRefs(refs)
	if len(names) == 0 {
		return 0, nil
	}
	// Going back to pending clears the decision; any other status stamps it. The
	// registry is already locked as the gateway's, so the join is not repeated.
	const query = `
		UPDATE registry_tools t
		   SET status     = $2,
		       decided_at = CASE WHEN $2 = 'pending' THEN NULL ELSE now() END,
		       decided_by = CASE WHEN $2 = 'pending' THEN NULL ELSE NULLIF($3, '') END
		  FROM unnest($4::text[], $5::text[]) AS x(name, fp)
		 WHERE t.registry_id = $1
		   AND t.tool_name = x.name
		   AND t.fingerprint = x.fp`
	cmd, err := tx.Exec(ctx, query, registryID, string(status), decidedBy, names, fingerprints)
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
	return r.withBump(ctx, gatewayID, registryID, func(tx pgx.Tx, _ string) (bool, error) {
		return approveAllTx(ctx, tx, registryID, tools, decidedBy)
	})
}

func (r *PinnedToolRepository) Pin(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	tools, unchecked []domain.ToolCandidate,
	decidedBy string,
) error {
	const setPolicy = `UPDATE registries SET tool_policy = 'pinned' WHERE id = $1 AND gateway_id = $2`
	return r.withBump(ctx, gatewayID, registryID, func(tx pgx.Tx, kind string) (bool, error) {
		if domain.Type(kind) != domain.TypeMCP {
			return false, fmt.Errorf("%w: pinned is only valid for MCP registries", domain.ErrInvalidToolPolicy)
		}
		// The confirmed list is exact: whatever was approved and is not on it goes
		// back to pending, so unchecking a tool in the console withdraws it.
		if err := demoteUnlisted(ctx, tx, registryID, tools); err != nil {
			return false, err
		}
		if _, err := approveAllTx(ctx, tx, registryID, tools, decidedBy); err != nil {
			return false, err
		}
		// Unchecked live tools become pending rows in this same transaction, after
		// the demotions so the caps see the final pending count.
		if names, fps, defs := splitCandidates(unchecked); len(names) > 0 {
			if _, _, err := insertPendingCapped(ctx, tx, registryID, names, fps, defs); err != nil {
				return false, fmt.Errorf("pinned tool repository: record unchecked tools: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, setPolicy, registryID, gatewayID); err != nil {
			return false, fmt.Errorf("pinned tool repository: set policy: %w", err)
		}
		return true, nil
	})
}

// demoteUnlisted returns every approved row that is not in tools to pending,
// clearing its decision. Rejected rows are left alone.
func demoteUnlisted(ctx context.Context, tx pgx.Tx, registryID ids.RegistryID, tools []domain.ToolCandidate) error {
	names, fingerprints, _ := splitCandidates(tools)
	const query = `
		UPDATE registry_tools t
		   SET status = 'pending', decided_at = NULL, decided_by = NULL
		 WHERE t.registry_id = $1
		   AND t.status = 'approved'
		   AND NOT EXISTS (
		       SELECT 1 FROM unnest($2::text[], $3::text[]) AS x(name, fp)
		        WHERE x.name = t.tool_name AND x.fp = t.fingerprint)`
	if _, err := tx.Exec(ctx, query, registryID, names, fingerprints); err != nil {
		return fmt.Errorf("pinned tool repository: withdraw unlisted approvals: %w", err)
	}
	return nil
}

func approveAllTx(
	ctx context.Context,
	tx pgx.Tx,
	registryID ids.RegistryID,
	tools []domain.ToolCandidate,
	decidedBy string,
) (bool, error) {
	names, fingerprints, definitions := splitCandidates(tools)
	if len(names) == 0 {
		return false, nil
	}
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
	if _, err := tx.Exec(ctx, upsert, registryID, decidedBy, names, fingerprints, definitions); err != nil {
		return false, fmt.Errorf("pinned tool repository: approve all: %w", err)
	}
	return true, nil
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
