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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	fieldLoginClient    = "auths.config.oauth2.client_secret"
	fieldExchangeClient = "auths.config.oauth2.exchange_client_secret"
)

var (
	errNoSealer           = errors.New("auth repository: stored value is encrypted but no field sealer is configured")
	errEncryptedWritesOff = errors.New("auth repository: encrypted writes are not enabled")
)

// WithFieldSealer lets the repository read the oauth2 client secrets stored
// encrypted in config. With encryptWrites it also stores them encrypted;
// without it writes stay unencrypted, so replicas that cannot read the
// encrypted form keep working during a rollout.
func WithFieldSealer(sealer *crypto.FieldSealer, encryptWrites bool) Option {
	return func(r *Repository) {
		r.sealer = sealer
		r.encryptWrites = sealer != nil && encryptWrites
	}
}

func sealedAAD(field string, id ids.AuthID) string { return field + "|" + id.String() }

// marshalConfig encodes c for storage, with its client secrets encrypted for
// the auth id when encrypted writes are on. c is not modified.
func (r *Repository) marshalConfig(id ids.AuthID, c domain.Config) ([]byte, error) {
	if !r.encryptWrites {
		return json.Marshal(c)
	}
	return r.marshalSealedConfig(id, c)
}

func (r *Repository) marshalSealedConfig(id ids.AuthID, c domain.Config) ([]byte, error) {
	if c.OAuth2 != nil {
		oauth2 := *c.OAuth2
		var err error
		if oauth2.ClientSecret, err = r.sealer.Seal(sealedAAD(fieldLoginClient, id), oauth2.ClientSecret); err != nil {
			return nil, err
		}
		if oauth2.ExchangeClientSecret, err = r.sealer.Seal(sealedAAD(fieldExchangeClient, id), oauth2.ExchangeClientSecret); err != nil {
			return nil, err
		}
		c.OAuth2 = &oauth2
	}
	return json.Marshal(c)
}

// openConfig decrypts c's client secrets in place. Values stored before
// encryption was introduced are kept as they are. onFailure decides what a
// value that cannot be decrypted becomes: returning an error stops, returning
// nil leaves the field empty.
func (r *Repository) openConfig(
	id ids.AuthID,
	c *domain.Config,
	onFailure func(field, stored string, err error) error,
) error {
	if c == nil || c.OAuth2 == nil {
		return nil
	}
	open := func(field, stored string) (string, error) {
		plain, err := r.openField(sealedAAD(field, id), stored)
		if err == nil {
			return plain, nil
		}
		return "", onFailure(field, stored, err)
	}
	var err error
	if c.OAuth2.ClientSecret, err = open(fieldLoginClient, c.OAuth2.ClientSecret); err != nil {
		return err
	}
	c.OAuth2.ExchangeClientSecret, err = open(fieldExchangeClient, c.OAuth2.ExchangeClientSecret)
	return err
}

// openConfigForRead decrypts c for a read. A secret that cannot be decrypted
// is returned empty, reported and counted, so the auth keeps working where it
// can and the secret can be entered again.
func (r *Repository) openConfigForRead(ctx context.Context, id ids.AuthID, c *domain.Config) {
	_ = r.openConfig(id, c, func(field, stored string, err error) error {
		reportUnreadableField(ctx, id, field, stored, err)
		if field == fieldExchangeClient {
			c.OAuth2.ExchangeSecretUnreadable = true
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

// encodeConfigForUpdate encodes c for an update of row id. A client secret
// that comes back empty because it could not be decrypted on read must not
// overwrite what is stored, so an empty secret whose stored value still cannot
// be decrypted is kept as it is, as long as its client id is unchanged. The
// stored row is read under a row lock in tx.
func (r *Repository) encodeConfigForUpdate(
	ctx context.Context,
	tx pgx.Tx,
	id ids.AuthID,
	gatewayID ids.GatewayID,
	c domain.Config,
) ([]byte, error) {
	raw, err := r.marshalConfig(id, c)
	if err != nil || c.OAuth2 == nil || (c.OAuth2.ClientSecret != "" && c.OAuth2.ExchangeClientSecret != "") {
		return raw, err
	}
	const lock = `SELECT config FROM auths WHERE id = $1 AND gateway_id = $2 FOR UPDATE`
	var storedRaw []byte
	if err := tx.QueryRow(ctx, lock, id, gatewayID).Scan(&storedRaw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return raw, nil
		}
		return nil, fmt.Errorf("auth repository: lock config: %w", err)
	}
	if len(storedRaw) == 0 {
		return raw, nil
	}
	var stored domain.Config
	if err := json.Unmarshal(storedRaw, &stored); err != nil {
		return nil, fmt.Errorf("auth repository: stored config: %w: %w", commonerrors.ErrCorruptData, err)
	}
	if stored.OAuth2 == nil {
		return raw, nil
	}
	var out domain.Config
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	changed := false
	if out.OAuth2.ClientSecret == "" && sameClient(out.OAuth2.ClientID, stored.OAuth2.ClientID) &&
		r.unopenable(sealedAAD(fieldLoginClient, id), stored.OAuth2.ClientSecret) {
		out.OAuth2.ClientSecret = stored.OAuth2.ClientSecret
		changed = true
	}
	if out.OAuth2.ExchangeClientSecret == "" && sameClient(out.OAuth2.ExchangeClientID, stored.OAuth2.ExchangeClientID) &&
		r.unopenable(sealedAAD(fieldExchangeClient, id), stored.OAuth2.ExchangeClientSecret) {
		out.OAuth2.ExchangeClientSecret = stored.OAuth2.ExchangeClientSecret
		changed = true
	}
	if !changed {
		return raw, nil
	}
	return json.Marshal(out)
}

func sameClient(a, b string) bool {
	a = strings.TrimSpace(a)
	return a != "" && a == strings.TrimSpace(b)
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

func reportUnreadableField(ctx context.Context, id ids.AuthID, field, stored string, err error) {
	slog.ErrorContext(ctx, "auth repository: stored credential cannot be decrypted; returning it empty",
		slog.String("component", "auth_repository"),
		slog.String("auth_id", id.String()),
		slog.String("field", field),
		slog.String("key_id", crypto.SealedKeyID(stored)),
		slog.String("error", err.Error()))
	counter, cerr := otel.Meter("trustgate/auth_repository").Int64Counter(
		"trustgate.stored_secrets.unreadable_fields",
		metric.WithDescription("stored credentials returned empty because they could not be decrypted"),
	)
	if cerr != nil {
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(attribute.String("table", "auths")))
}

func hasUnsealedSecrets(c domain.Config) bool {
	if c.OAuth2 == nil {
		return false
	}
	return isUnsealed(c.OAuth2.ClientSecret) || isUnsealed(c.OAuth2.ExchangeClientSecret)
}

func isUnsealed(v string) bool { return v != "" && !crypto.IsSealed(v) }

// SealStoredSecrets encrypts, one row lock at a time, the client secrets of
// every auth config stored before encryption was introduced. Rows already
// encrypted are not written, so running it again, or on several replicas at
// once, is safe. A row that cannot be read or written is logged, counted in
// failed and left as it was; the pass carries on. The decrypted config is
// unchanged, so no config-snapshot change marker is recorded. It needs
// encrypted writes enabled.
func (r *Repository) SealStoredSecrets(ctx context.Context) (sealed, failed int, err error) {
	if !r.encryptWrites {
		return 0, 0, errEncryptedWritesOff
	}
	const candidates = `SELECT id FROM auths WHERE config::text LIKE '%client_secret%' ORDER BY id`
	rows, err := r.conn.Pool.Query(ctx, candidates)
	if err != nil {
		return 0, 0, fmt.Errorf("auth repository: list configs: %w", err)
	}
	authIDs, err := pgx.CollectRows(rows, pgx.RowTo[ids.AuthID])
	if err != nil {
		return 0, 0, fmt.Errorf("auth repository: list configs: %w", err)
	}
	for _, id := range authIDs {
		if err := ctx.Err(); err != nil {
			return sealed, failed, err
		}
		done, err := r.sealStoredConfig(ctx, id)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return sealed, failed, ctxErr
			}
			failed++
			slog.ErrorContext(ctx, "auth repository: stored credentials backfill skipped an auth",
				slog.String("component", "auth_repository"),
				slog.String("auth_id", id.String()),
				slog.String("error", err.Error()))
			continue
		}
		if done {
			sealed++
		}
	}
	return sealed, failed, nil
}

func (r *Repository) sealStoredConfig(ctx context.Context, id ids.AuthID) (bool, error) {
	const lock = `SELECT config FROM auths WHERE id = $1 FOR UPDATE`
	const update = `UPDATE auths SET config = $2 WHERE id = $1`
	done := false
	err := database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		done = false
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
		var cfg domain.Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("%w: %w", commonerrors.ErrCorruptData, err)
		}
		if !hasUnsealedSecrets(cfg) {
			return nil
		}
		// A value that does not decrypt is never rewritten: it may still open
		// under the right key, and re-saving it would replace it with nothing.
		if err := r.openConfig(id, &cfg, func(field, stored string, err error) error {
			return fmt.Errorf("%w: %s (key %s): %w", commonerrors.ErrCorruptData, field, crypto.SealedKeyID(stored), err)
		}); err != nil {
			return err
		}
		payload, err := r.marshalSealedConfig(id, cfg)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, update, id, payload); err != nil {
			return err
		}
		done = true
		return nil
	})
	return done, err
}
