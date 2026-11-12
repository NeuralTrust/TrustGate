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
	"slices"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

const (
	fieldMCPAuthValue         = "registries.mcp_target.auth.value"
	fieldMCPAuthClient        = "registries.mcp_target.auth.client_secret"
	fieldMCPHeaderPrefix      = "registries.mcp_target.headers."
	fieldProviderHeaderPrefix = "registries.provider_options.headers."
	fieldA2AAuthValue         = "registries.a2a_target.auth.value"
	fieldA2AAuthClient        = "registries.a2a_target.auth.client_secret"
	fieldA2AHeaderPrefix      = "registries.a2a_target.headers."
	fieldA2AAWSSecret         = "registries.a2a_target.cloud_auth.aws.secret_access_key" // #nosec G101 -- config field path, not a credential
	fieldA2AAWSSession        = "registries.a2a_target.cloud_auth.aws.session_token"
	fieldA2AAzureSecret       = "registries.a2a_target.cloud_auth.azure.client_secret" // #nosec G101 -- config field path, not a credential
	fieldA2AGCPKey            = "registries.a2a_target.cloud_auth.gcp.service_account_json"
)

// sealedFields names the field paths a target's auth secrets and static
// headers are sealed under.
type sealedFields struct {
	authValue, authClient, headerPrefix string
}

var (
	mcpFields = sealedFields{fieldMCPAuthValue, fieldMCPAuthClient, fieldMCPHeaderPrefix}
	a2aFields = sealedFields{fieldA2AAuthValue, fieldA2AAuthClient, fieldA2AHeaderPrefix}
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

func sealedAAD(field string, id ids.RegistryID) string { return crypto.FieldAAD(field, id.String()) }

// sealMCPTarget returns a copy of t whose credentials are encrypted for the
// registry id. t is not modified: the caller keeps caching and returning the
// plaintext object.
func (r *Repository) sealMCPTarget(id ids.RegistryID, t *domain.MCPTarget) (*domain.MCPTarget, error) {
	return r.sealCredentials(mcpFields, id, t)
}

func (r *Repository) sealCredentials(f sealedFields, id ids.RegistryID, t *domain.MCPTarget) (*domain.MCPTarget, error) {
	if t == nil || r.sealer == nil {
		return t, nil
	}
	out := *t
	if t.Auth != nil {
		auth := *t.Auth
		var err error
		if auth.Value, err = r.sealer.Seal(sealedAAD(f.authValue, id), auth.Value); err != nil {
			return nil, err
		}
		if auth.ClientSecret, err = r.sealer.Seal(sealedAAD(f.authClient, id), auth.ClientSecret); err != nil {
			return nil, err
		}
		out.Auth = &auth
	}
	if t.Headers != nil {
		out.Headers = make(map[string]string, len(t.Headers))
		for name, value := range t.Headers {
			sealed, err := r.sealer.Seal(sealedAAD(f.headerPrefix+name, id), value)
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
	return r.openCredentials(mcpFields, id, t, onFailure)
}

func (r *Repository) openCredentials(
	f sealedFields,
	id ids.RegistryID,
	t *domain.MCPTarget,
	onFailure func(field, stored string, err error) error,
) error {
	if t == nil {
		return nil
	}
	open := func(field, stored string) (string, error) {
		plain, err := r.sealer.OpenField(sealedAAD(field, id), stored)
		if err == nil {
			return plain, nil
		}
		return "", onFailure(field, stored, err)
	}
	if t.Auth != nil {
		var err error
		if t.Auth.Value, err = open(f.authValue, t.Auth.Value); err != nil {
			return err
		}
		if t.Auth.ClientSecret, err = open(f.authClient, t.Auth.ClientSecret); err != nil {
			return err
		}
	}
	for name, value := range t.Headers {
		plain, err := open(f.headerPrefix+name, value)
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
	r.openCredentialsForRead(ctx, mcpFields, id, t)
}

func (r *Repository) openCredentialsForRead(ctx context.Context, f sealedFields, id ids.RegistryID, t *domain.MCPTarget) {
	// The callback never fails, so neither does the walk.
	_ = r.openCredentials(f, id, t, func(field, stored string, err error) error {
		crypto.ReportUnreadableField(ctx, "registries", id.String(), field, stored, err)
		switch {
		case field == f.authValue || field == f.authClient:
			t.Auth.SecretUnreadable = true
		case strings.HasPrefix(field, f.headerPrefix):
			t.UnreadableHeaders = append(t.UnreadableHeaders, strings.TrimPrefix(field, f.headerPrefix))
		}
		return nil
	})
	slices.Sort(t.UnreadableHeaders)
}

// unopenable reports whether stored is an encrypted value this repository
// cannot decrypt for aad: another key, another row, or no sealer at all.
func (r *Repository) unopenable(aad, stored string) bool {
	return crypto.IsSealed(stored) && !r.sealer.CanOpen(aad, stored)
}

// encodeMCPTargetForUpdate encodes t for an update of row id. A credential
// that came back empty because it could not be decrypted on read must not
// overwrite what is stored. For every empty credential that t marks as
// unreadable on read, or whose stored value still cannot be decrypted, the
// stored value is kept as it is, even when another update has since replaced
// it with one that reads. The stored row is read under a row lock in tx.
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
	out, err := r.credentialsForUpdate(mcpFields, id, t, func() (*domain.MCPTarget, error) {
		return lockStoredMCPTarget(ctx, tx, id, gatewayID)
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// credentialsForUpdate returns a copy of t with its credentials as they are
// written: sealed when encrypted writes are on, and each empty unreadable
// credential replaced by the stored value lockStored returns.
func (r *Repository) credentialsForUpdate(
	f sealedFields,
	id ids.RegistryID,
	t *domain.MCPTarget,
	lockStored func() (*domain.MCPTarget, error),
) (*domain.MCPTarget, error) {
	out := *t
	if r.encryptWrites {
		sealed, err := r.sealCredentials(f, id, t)
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
		stored, err := lockStored()
		if err != nil {
			return nil, err
		}
		r.keepUnreadable(f, id, t, &out, stored)
	}
	return &out, nil
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
// leaves empty and that was unreadable: marked so on in when it was read, or
// still undecryptable now. An auth secret is only kept while the auth mode is
// unchanged: a new mode drops the old credential. Header names match
// case-insensitively, as HTTP header names do.
func (r *Repository) keepUnreadableCredentials(id ids.RegistryID, in, out, stored *domain.MCPTarget) {
	r.keepUnreadable(mcpFields, id, in, out, stored)
}

func (r *Repository) keepUnreadable(f sealedFields, id ids.RegistryID, in, out, stored *domain.MCPTarget) {
	if stored == nil {
		return
	}
	if out.Auth != nil && stored.Auth != nil && out.Auth.Mode == stored.Auth.Mode {
		marked := in.Auth != nil && in.Auth.SecretUnreadable
		if out.Auth.Value == "" && stored.Auth.Value != "" &&
			((marked && out.Auth.Mode == domain.MCPAuthModeStatic) || r.unopenable(sealedAAD(f.authValue, id), stored.Auth.Value)) {
			out.Auth.Value = stored.Auth.Value
		}
		if out.Auth.ClientSecret == "" && stored.Auth.ClientSecret != "" &&
			((marked && out.Auth.Mode != domain.MCPAuthModeStatic) || r.unopenable(sealedAAD(f.authClient, id), stored.Auth.ClientSecret)) {
			out.Auth.ClientSecret = stored.Auth.ClientSecret
		}
	}
	for name, value := range out.Headers {
		if value != "" {
			continue
		}
		storedName, prev := storedHeader(stored.Headers, name)
		if prev == "" {
			continue
		}
		marked := slices.ContainsFunc(in.UnreadableHeaders, func(n string) bool { return strings.EqualFold(n, name) })
		if marked || r.unopenable(sealedAAD(f.headerPrefix+storedName, id), prev) {
			out.Headers[name] = r.resealHeader(id, f.headerPrefix, storedName, name, prev)
		}
	}
}

func storedHeader(headers map[string]string, name string) (string, string) {
	if v, ok := headers[name]; ok {
		return name, v
	}
	for _, k := range slices.Sorted(maps.Keys(headers)) {
		if strings.EqualFold(k, name) {
			return k, headers[k]
		}
	}
	return "", ""
}

// resealHeader returns a kept stored header value for the name it is written
// under. The field path is part of what a value is sealed for, so a value kept
// under a name whose case changed is re-sealed when it can be read, and kept
// as stored otherwise.
func (r *Repository) resealHeader(id ids.RegistryID, prefix, storedName, name, stored string) string {
	if storedName == name || !crypto.IsSealed(stored) {
		return stored
	}
	plain, err := r.sealer.OpenField(sealedAAD(prefix+storedName, id), stored)
	if err != nil {
		return stored
	}
	if !r.encryptWrites {
		return plain
	}
	resealed, err := r.sealer.Seal(sealedAAD(prefix+name, id), plain)
	if err != nil {
		return stored
	}
	return resealed
}

func (r *Repository) sealProviderOptionHeaders(id ids.RegistryID, options map[string]any) (map[string]any, error) {
	if !r.encryptWrites || r.sealer == nil {
		return options, nil
	}
	headers, ok := domain.ProviderOptionHeaders(options)
	if !ok || len(headers) == 0 {
		return options, nil
	}
	sealed := make(map[string]string, len(headers))
	for name, value := range headers {
		stored, err := r.sealer.Seal(sealedAAD(fieldProviderHeaderPrefix+name, id), value)
		if err != nil {
			return nil, err
		}
		sealed[name] = stored
	}
	out := maps.Clone(options)
	out["headers"] = sealed
	return out, nil
}

func (r *Repository) openProviderOptionHeaders(ctx context.Context, id ids.RegistryID, target *domain.LLMTarget) {
	if target == nil {
		return
	}
	headers, ok := domain.ProviderOptionHeaders(target.ProviderOptions)
	if !ok || len(headers) == 0 {
		return
	}
	opened := make(map[string]string, len(headers))
	var unreadable []string
	for name, value := range headers {
		plain, err := r.sealer.OpenField(sealedAAD(fieldProviderHeaderPrefix+name, id), value)
		if err != nil {
			crypto.ReportUnreadableField(ctx, "registries", id.String(), fieldProviderHeaderPrefix+name, value, err)
			opened[name] = ""
			unreadable = append(unreadable, name)
			continue
		}
		opened[name] = plain
	}
	slices.Sort(unreadable)
	target.ProviderOptions["headers"] = opened
	target.UnreadableProviderHeaders = unreadable
}

func (r *Repository) encodeProviderOptionsForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	b *domain.Registry,
) ([]byte, error) {
	options := b.ProviderOptions()
	if len(options) == 0 {
		return nil, nil
	}
	out, err := r.sealProviderOptionHeaders(b.ID, options)
	if err != nil {
		return nil, err
	}
	var marks []string
	if b.LLMTarget != nil {
		marks = b.LLMTarget.UnreadableProviderHeaders
	}
	if len(marks) > 0 {
		out = cloneProviderOptions(out)
		stored, err := lockStoredProviderOptions(ctx, tx, b.ID, b.GatewayID)
		if err != nil {
			return nil, err
		}
		r.keepUnreadableProviderHeaders(b.ID, marks, out, stored)
	}
	return json.Marshal(out)
}

func cloneProviderOptions(options map[string]any) map[string]any {
	if options == nil {
		return nil
	}
	out := maps.Clone(options)
	switch headers := out["headers"].(type) {
	case map[string]string:
		out["headers"] = maps.Clone(headers)
	case map[string]any:
		out["headers"] = maps.Clone(headers)
	}
	return out
}

func lockStoredProviderOptions(
	ctx context.Context,
	tx pgx.Tx,
	id ids.RegistryID,
	gatewayID ids.GatewayID,
) (map[string]any, error) {
	const lock = `SELECT provider_options FROM registries WHERE id = $1 AND gateway_id = $2 FOR UPDATE`
	var raw []byte
	if err := tx.QueryRow(ctx, lock, id, gatewayID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("registry repository: lock provider_options: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("registry repository: stored provider_options: %w: %w", commonerrors.ErrCorruptData, err)
	}
	return stored, nil
}

func (r *Repository) keepUnreadableProviderHeaders(id ids.RegistryID, marks []string, out, stored map[string]any) {
	if len(marks) == 0 || stored == nil || out == nil {
		return
	}
	storedHeaders, _ := domain.ProviderOptionHeaders(stored)
	for _, name := range marks {
		if headerValue(out, name) != "" {
			continue
		}
		storedName, prev := storedHeader(storedHeaders, name)
		if prev == "" {
			continue
		}
		setProviderOptionHeader(out, name, r.resealHeader(id, fieldProviderHeaderPrefix, storedName, name, prev))
	}
}

func headerValue(options map[string]any, name string) string {
	headers, ok := domain.ProviderOptionHeaders(options)
	if !ok {
		return ""
	}
	if value, ok := headers[name]; ok {
		return value
	}
	_, value := storedHeader(headers, name)
	return value
}

func setProviderOptionHeader(options map[string]any, name, value string) {
	switch headers := options["headers"].(type) {
	case map[string]string:
		if _, ok := headers[name]; ok {
			headers[name] = value
			return
		}
		for _, key := range slices.Sorted(maps.Keys(headers)) {
			if strings.EqualFold(key, name) {
				headers[key] = value
				return
			}
		}
		headers[name] = value
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(headers)) {
			if strings.EqualFold(key, name) {
				headers[key] = value
				return
			}
		}
		headers[name] = value
	default:
		options["headers"] = map[string]string{name: value}
	}
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
		return report, crypto.ErrEncryptedWritesOff
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
	rows, err := database.Reader(ctx, r.conn.Pool).Query(ctx, query)
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
	const lock = `SELECT mcp_target, gateway_id FROM registries WHERE id = $1 FOR UPDATE`
	const update = `UPDATE registries SET mcp_target = $2 WHERE id = $1`
	err = database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		encrypted, fixed = false, false
		var (
			raw       []byte
			gatewayID ids.GatewayID
		)
		if err := tx.QueryRow(ctx, lock, id).Scan(&raw, &gatewayID); err != nil {
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
			if err := r.outbox.AppendGatewayTx(ctx, tx, gatewayID); err != nil {
				return err
			}
		}
		encrypted, fixed = needsSealing, changed
		return nil
	})
	return encrypted, fixed, err
}

func credentialShell(t *domain.A2ATarget) *domain.MCPTarget {
	return &domain.MCPTarget{Headers: t.Headers, Auth: t.Auth, UnreadableHeaders: t.UnreadableHeaders}
}

func cloneCloudAuth(c *domain.A2ACloudAuth) *domain.A2ACloudAuth {
	if c == nil {
		return nil
	}
	out := *c
	if c.AWS != nil {
		aws := *c.AWS
		out.AWS = &aws
	}
	if c.Azure != nil {
		azure := *c.Azure
		out.Azure = &azure
	}
	if c.GCP != nil {
		gcp := *c.GCP
		out.GCP = &gcp
	}
	return &out
}

// cloudSecrets maps the sealed field path of each secret of c to that secret.
func cloudSecrets(c *domain.A2ACloudAuth) map[string]*string {
	out := map[string]*string{}
	if c == nil {
		return out
	}
	if c.AWS != nil {
		out[fieldA2AAWSSecret] = &c.AWS.SecretAccessKey
		out[fieldA2AAWSSession] = &c.AWS.SessionToken
	}
	if c.Azure != nil {
		out[fieldA2AAzureSecret] = &c.Azure.ClientSecret
	}
	if c.GCP != nil {
		out[fieldA2AGCPKey] = &c.GCP.ServiceAccountJSON
	}
	return out
}

// sealA2ATarget returns a copy of t whose credentials are encrypted for the
// registry id. t is not modified.
func (r *Repository) sealA2ATarget(id ids.RegistryID, t *domain.A2ATarget) (*domain.A2ATarget, error) {
	shell, err := r.sealCredentials(a2aFields, id, credentialShell(t))
	if err != nil {
		return nil, err
	}
	out := *t
	out.Headers, out.Auth = shell.Headers, shell.Auth
	out.CloudAuth = cloneCloudAuth(t.CloudAuth)
	for field, value := range cloudSecrets(out.CloudAuth) {
		if *value, err = r.sealer.Seal(sealedAAD(field, id), *value); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// openA2ATargetForRead decrypts t for a read. A credential that cannot be
// decrypted is returned empty, reported and marked, as for MCP targets.
func (r *Repository) openA2ATargetForRead(ctx context.Context, id ids.RegistryID, t *domain.A2ATarget) {
	shell := credentialShell(t)
	r.openCredentialsForRead(ctx, a2aFields, id, shell)
	t.UnreadableHeaders = shell.UnreadableHeaders
	for field, value := range cloudSecrets(t.CloudAuth) {
		plain, err := r.sealer.OpenField(sealedAAD(field, id), *value)
		if err != nil {
			crypto.ReportUnreadableField(ctx, "registries", id.String(), field, *value, err)
			t.CloudAuth.SecretUnreadable = true
		}
		*value = plain
	}
}

// encodeA2ATargetForUpdate encodes t for an update of row id. A credential
// that came back empty because it could not be decrypted on read keeps its
// stored value. The stored row is read under a row lock in tx.
func (r *Repository) encodeA2ATargetForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	id ids.RegistryID,
	gatewayID ids.GatewayID,
	t *domain.A2ATarget,
) ([]byte, error) {
	if t == nil {
		return nil, nil
	}
	var stored *domain.A2ATarget
	lockStored := func() (*domain.A2ATarget, error) {
		if stored != nil {
			return stored, nil
		}
		var err error
		stored, err = lockStoredA2ATarget(ctx, tx, id, gatewayID)
		return stored, err
	}
	shell, err := r.credentialsForUpdate(a2aFields, id, credentialShell(t), func() (*domain.MCPTarget, error) {
		s, err := lockStored()
		if err != nil || s == nil {
			return nil, err
		}
		return credentialShell(s), nil
	})
	if err != nil {
		return nil, err
	}
	out := *t
	out.Headers, out.Auth = shell.Headers, shell.Auth
	out.CloudAuth = cloneCloudAuth(t.CloudAuth)
	for field, value := range cloudSecrets(out.CloudAuth) {
		if *value == "" && t.CloudAuth.SecretUnreadable {
			s, err := lockStored()
			if err != nil {
				return nil, err
			}
			if s != nil {
				if prev, ok := cloudSecrets(s.CloudAuth)[field]; ok {
					*value = *prev
				}
			}
			continue
		}
		if r.encryptWrites {
			if *value, err = r.sealer.Seal(sealedAAD(field, id), *value); err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(&out)
}

func lockStoredA2ATarget(ctx context.Context, tx pgx.Tx, id ids.RegistryID, gatewayID ids.GatewayID) (*domain.A2ATarget, error) {
	const lock = `SELECT a2a_target FROM registries WHERE id = $1 AND gateway_id = $2 FOR UPDATE`
	var raw []byte
	if err := tx.QueryRow(ctx, lock, id, gatewayID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("registry repository: lock a2a_target: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var stored domain.A2ATarget
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("registry repository: stored a2a_target: %w: %w", commonerrors.ErrCorruptData, err)
	}
	return &stored, nil
}
