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

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	fieldMCPAuthValue    = "registries.mcp_target.auth.value"
	fieldMCPAuthClient   = "registries.mcp_target.auth.client_secret"
	fieldMCPHeaderPrefix = "registries.mcp_target.headers."
)

var (
	errNoSealer           = errors.New("registry repository: stored value is encrypted but no field sealer is configured")
	errEncryptedWritesOff = errors.New("registry repository: encrypted writes are not enabled")
)

// WithFieldSealer lets the repository read credentials stored encrypted in
// mcp_target (auth value, client secret, static header values). With
// encryptWrites it also stores them encrypted; without it writes stay
// unencrypted, so replicas that cannot read the encrypted form keep working
// during a rollout.
func WithFieldSealer(sealer *crypto.FieldSealer, encryptWrites bool) Option {
	return func(r *Repository) {
		r.sealer = sealer
		r.encryptWrites = sealer != nil && encryptWrites
	}
}

func sealedAAD(field string, id ids.RegistryID) string { return field + "|" + id.String() }

// sealMCPTarget returns a copy of t whose credentials are encrypted for the
// registry id. t is not modified: the caller keeps caching and returning the
// plaintext object.
func (r *Repository) sealMCPTarget(id ids.RegistryID, t *domain.MCPTarget) (*domain.MCPTarget, error) {
	if t == nil || r.sealer == nil {
		return t, nil
	}
	out := *t
	if t.Auth != nil {
		auth := *t.Auth
		var err error
		if auth.Value, err = r.sealer.Seal(sealedAAD(fieldMCPAuthValue, id), auth.Value); err != nil {
			return nil, err
		}
		if auth.ClientSecret, err = r.sealer.Seal(sealedAAD(fieldMCPAuthClient, id), auth.ClientSecret); err != nil {
			return nil, err
		}
		out.Auth = &auth
	}
	if t.Headers != nil {
		out.Headers = make(map[string]string, len(t.Headers))
		for name, value := range t.Headers {
			sealed, err := r.sealer.Seal(sealedAAD(fieldMCPHeaderPrefix+name, id), value)
			if err != nil {
				return nil, err
			}
			out.Headers[name] = sealed
		}
	}
	return &out, nil
}

// openMCPTarget decrypts t's credentials in place. Values stored before
// encryption was introduced are kept as they are. onFailure decides what a
// value that cannot be decrypted becomes: returning an error stops, returning
// nil leaves the field empty.
func (r *Repository) openMCPTarget(
	id ids.RegistryID,
	t *domain.MCPTarget,
	onFailure func(field, stored string, err error) error,
) error {
	if t == nil {
		return nil
	}
	open := func(field, stored string) (string, error) {
		plain, err := r.openField(sealedAAD(field, id), stored)
		if err == nil {
			return plain, nil
		}
		return "", onFailure(field, stored, err)
	}
	if t.Auth != nil {
		var err error
		if t.Auth.Value, err = open(fieldMCPAuthValue, t.Auth.Value); err != nil {
			return err
		}
		if t.Auth.ClientSecret, err = open(fieldMCPAuthClient, t.Auth.ClientSecret); err != nil {
			return err
		}
	}
	for name, value := range t.Headers {
		plain, err := open(fieldMCPHeaderPrefix+name, value)
		if err != nil {
			return err
		}
		t.Headers[name] = plain
	}
	return nil
}

// openMCPTargetForRead decrypts t for a read. A credential that cannot be
// decrypted is returned empty, reported and counted, so the registry keeps
// routing and listing and the credential can be entered again.
func (r *Repository) openMCPTargetForRead(ctx context.Context, id ids.RegistryID, t *domain.MCPTarget) {
	_ = r.openMCPTarget(id, t, func(field, stored string, err error) error {
		reportUnreadableField(ctx, id, field, stored, err)
		if field == fieldMCPAuthValue || field == fieldMCPAuthClient {
			t.Auth.SecretUnreadable = true
		}
		return nil
	})
}

// unopenable reports whether stored is an encrypted value this repository
// cannot decrypt for aad: another key, another row, or no sealer at all.
func (r *Repository) unopenable(aad, stored string) bool {
	if !crypto.IsSealed(stored) {
		return false
	}
	_, err := r.openField(aad, stored)
	return err != nil
}

// encodeMCPTargetForUpdate encodes t for an update of row id. A credential
// that comes back empty because it could not be decrypted on read must not
// overwrite what is stored, so for every empty credential whose stored value
// still cannot be decrypted, the stored value is kept as it is. The stored row
// is read under a row lock in tx.
func (r *Repository) encodeMCPTargetForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	id ids.RegistryID,
	gatewayID ids.GatewayID,
	t *domain.MCPTarget,
) ([]byte, error) {
	if t == nil {
		return nil, nil
	}
	out := *t
	if r.encryptWrites {
		sealed, err := r.sealMCPTarget(id, t)
		if err != nil {
			return nil, err
		}
		out = *sealed
	} else {
		if t.Auth != nil {
			auth := *t.Auth
			out.Auth = &auth
		}
		out.Headers = maps.Clone(t.Headers)
	}
	if hasEmptyCredential(t) {
		stored, err := lockStoredMCPTarget(ctx, tx, id, gatewayID)
		if err != nil {
			return nil, err
		}
		r.keepUnreadableCredentials(id, &out, stored)
	}
	return json.Marshal(&out)
}

func hasEmptyCredential(t *domain.MCPTarget) bool {
	if t.Auth != nil && (t.Auth.Value == "" || t.Auth.ClientSecret == "") {
		return true
	}
	for value := range maps.Values(t.Headers) {
		if value == "" {
			return true
		}
	}
	return false
}

func lockStoredMCPTarget(ctx context.Context, tx pgx.Tx, id ids.RegistryID, gatewayID ids.GatewayID) (*domain.MCPTarget, error) {
	const lock = `SELECT mcp_target FROM registries WHERE id = $1 AND gateway_id = $2 FOR UPDATE`
	var raw []byte
	if err := tx.QueryRow(ctx, lock, id, gatewayID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("registry repository: lock mcp_target: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var stored domain.MCPTarget
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("registry repository: stored mcp_target: %w: %w", commonerrors.ErrCorruptData, err)
	}
	return &stored, nil
}

// keepUnreadableCredentials copies into out every stored credential that out
// leaves empty and that this repository cannot decrypt. An auth secret is only
// kept while the auth mode is unchanged: a new mode drops the old credential.
func (r *Repository) keepUnreadableCredentials(id ids.RegistryID, out, stored *domain.MCPTarget) {
	if stored == nil {
		return
	}
	if out.Auth != nil && stored.Auth != nil && out.Auth.Mode == stored.Auth.Mode {
		if out.Auth.Value == "" && r.unopenable(sealedAAD(fieldMCPAuthValue, id), stored.Auth.Value) {
			out.Auth.Value = stored.Auth.Value
		}
		if out.Auth.ClientSecret == "" && r.unopenable(sealedAAD(fieldMCPAuthClient, id), stored.Auth.ClientSecret) {
			out.Auth.ClientSecret = stored.Auth.ClientSecret
		}
	}
	for name, value := range out.Headers {
		if value != "" {
			continue
		}
		if prev, ok := stored.Headers[name]; ok && r.unopenable(sealedAAD(fieldMCPHeaderPrefix+name, id), prev) {
			out.Headers[name] = prev
		}
	}
}

func (r *Repository) openField(aad, stored string) (string, error) {
	if !crypto.IsSealed(stored) {
		return stored, nil
	}
	if r.sealer == nil {
		return "", errNoSealer
	}
	return r.sealer.Open(aad, stored)
}

func reportUnreadableField(ctx context.Context, id ids.RegistryID, field, stored string, err error) {
	slog.ErrorContext(ctx, "registry repository: stored credential cannot be decrypted; returning it empty",
		slog.String("component", "registry_repository"),
		slog.String("registry_id", id.String()),
		slog.String("field", field),
		slog.String("key_id", crypto.SealedKeyID(stored)),
		slog.String("error", err.Error()))
	counter, cerr := otel.Meter("trustgate/registry_repository").Int64Counter(
		"trustgate.stored_secrets.unreadable_fields",
		metric.WithDescription("stored credentials returned empty because they could not be decrypted"),
	)
	if cerr != nil {
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(attribute.String("table", "registries")))
}

// hasUnsealedSecrets reports whether a stored target still holds a credential
// that is not encrypted.
func hasUnsealedSecrets(t *domain.MCPTarget) bool {
	if t == nil {
		return false
	}
	if t.Auth != nil && (isUnsealed(t.Auth.Value) || isUnsealed(t.Auth.ClientSecret)) {
		return true
	}
	for value := range maps.Values(t.Headers) {
		if isUnsealed(value) {
			return true
		}
	}
	return false
}

func isUnsealed(v string) bool { return v != "" && !crypto.IsSealed(v) }

// RewriteMCPTargets visits every stored MCP target, one row lock at a time, and
// re-saves the ones whose credentials are not yet encrypted or that fix
// changes. fix receives the decrypted target and reports whether it modified
// it; a modified target also records a config-snapshot change marker. Rows
// already encrypted and left alone by fix are not written, so running it again,
// or on several replicas at once, is safe. A row that cannot be read or written
// is logged, counted as failed and left as it was; the pass carries on. It
// needs encrypted writes enabled.
func (r *Repository) RewriteMCPTargets(
	ctx context.Context,
	fix func(*domain.MCPTarget) bool,
) (domain.SecretsRewriteReport, error) {
	var report domain.SecretsRewriteReport
	if !r.encryptWrites {
		return report, errEncryptedWritesOff
	}
	registryIDs, err := r.mcpTargetIDs(ctx)
	if err != nil {
		return report, err
	}
	for _, id := range registryIDs {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		report.Scanned++
		encrypted, fixed, err := r.rewriteMCPTarget(ctx, id, fix)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return report, ctxErr
			}
			report.Failed++
			slog.ErrorContext(ctx, "registry repository: stored credentials backfill skipped a registry",
				slog.String("component", "registry_repository"),
				slog.String("registry_id", id.String()),
				slog.String("error", err.Error()))
			continue
		}
		if encrypted {
			report.Encrypted++
		}
		if fixed {
			report.Fixed++
		}
	}
	return report, nil
}

func (r *Repository) mcpTargetIDs(ctx context.Context) ([]ids.RegistryID, error) {
	const query = `SELECT id FROM registries WHERE mcp_target IS NOT NULL ORDER BY id`
	rows, err := r.conn.Pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("registry repository: list mcp targets: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[ids.RegistryID])
}

func (r *Repository) rewriteMCPTarget(
	ctx context.Context,
	id ids.RegistryID,
	fix func(*domain.MCPTarget) bool,
) (encrypted, fixed bool, err error) {
	const lock = `SELECT mcp_target FROM registries WHERE id = $1 FOR UPDATE`
	const update = `UPDATE registries SET mcp_target = $2 WHERE id = $1`
	err = database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		encrypted, fixed = false, false
		var raw []byte
		if err := tx.QueryRow(ctx, lock, id).Scan(&raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if len(raw) == 0 {
			return nil
		}
		var target domain.MCPTarget
		if err := json.Unmarshal(raw, &target); err != nil {
			return fmt.Errorf("%w: %w", commonerrors.ErrCorruptData, err)
		}
		needsSealing := hasUnsealedSecrets(&target)
		// A value that does not decrypt is never rewritten: it may still open
		// under the right key, and re-saving it would replace it with nothing.
		if err := r.openMCPTarget(id, &target, func(field, stored string, err error) error {
			return fmt.Errorf("%w: %s (key %s): %w", commonerrors.ErrCorruptData, field, crypto.SealedKeyID(stored), err)
		}); err != nil {
			return err
		}
		changed := fix != nil && fix(&target)
		if !needsSealing && !changed {
			return nil
		}
		stored, err := r.sealMCPTarget(id, &target)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, update, id, payload); err != nil {
			return err
		}
		if changed {
			if err := r.outbox.AppendTx(ctx, tx); err != nil {
				return err
			}
		}
		encrypted, fixed = needsSealing, changed
		return nil
	})
	return encrypted, fixed, err
}
