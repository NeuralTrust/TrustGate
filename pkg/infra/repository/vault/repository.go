package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/jackc/pgx/v5"
)

var _ domain.Repository = (*Repository)(nil)

type Repository struct {
	conn   *database.Connection
	cipher domain.Encrypter
}

func NewRepository(conn *database.Connection, cipher domain.Encrypter) *Repository {
	return &Repository{conn: conn, cipher: cipher}
}

func (r *Repository) Upsert(ctx context.Context, c *domain.Credential) error {
	if c == nil {
		return errors.New("vault repository: nil credential")
	}
	access, err := r.cipher.Encrypt(c.AccessToken)
	if err != nil {
		return fmt.Errorf("vault repository: encrypt access token: %w", err)
	}
	refresh, err := r.cipher.Encrypt(c.RefreshToken)
	if err != nil {
		return fmt.Errorf("vault repository: encrypt refresh token: %w", err)
	}
	scopes, err := json.Marshal(c.Scopes)
	if err != nil {
		return fmt.Errorf("vault repository: marshal scopes: %w", err)
	}
	const query = `
		INSERT INTO vault_credentials
			(id, gateway_id, principal_sub, provider, account_ref, access_token, refresh_token, scopes, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (gateway_id, principal_sub, provider) DO UPDATE SET
			account_ref = EXCLUDED.account_ref,
			access_token = EXCLUDED.access_token,
			refresh_token = CASE WHEN EXCLUDED.refresh_token <> '' THEN EXCLUDED.refresh_token ELSE vault_credentials.refresh_token END,
			scopes = EXCLUDED.scopes,
			expires_at = EXCLUDED.expires_at,
			updated_at = EXCLUDED.updated_at`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query,
			c.ID, c.GatewayID, c.PrincipalSub, c.Provider, c.AccountRef,
			access, refresh, scopes, nullableTime(c.ExpiresAt), c.CreatedAt, time.Now().UTC(),
		)
		return err
	})
}

func (r *Repository) Find(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) (*domain.Credential, error) {
	const query = `
		SELECT id, gateway_id, principal_sub, provider, account_ref, access_token, refresh_token, scopes, expires_at, created_at, updated_at
		FROM vault_credentials
		WHERE gateway_id = $1 AND principal_sub = $2 AND provider = $3`
	row := r.conn.Pool.QueryRow(ctx, query, gatewayID, principalSub, provider)
	c, err := r.scan(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return c, err
}

func (r *Repository) ListByPrincipal(ctx context.Context, gatewayID ids.GatewayID, principalSub string) ([]*domain.Credential, error) {
	const query = `
		SELECT id, gateway_id, principal_sub, provider, account_ref, access_token, refresh_token, scopes, expires_at, created_at, updated_at
		FROM vault_credentials
		WHERE gateway_id = $1 AND principal_sub = $2
		ORDER BY provider`
	rows, err := r.conn.Pool.Query(ctx, query, gatewayID, principalSub)
	if err != nil {
		return nil, fmt.Errorf("vault repository: list: %w", err)
	}
	defer rows.Close()
	var out []*domain.Credential
	for rows.Next() {
		c, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Repository) Delete(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) error {
	const query = `DELETE FROM vault_credentials WHERE gateway_id = $1 AND principal_sub = $2 AND provider = $3`
	return database.WithTx(ctx, r.conn, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, query, gatewayID, principalSub, provider)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

func (r *Repository) scan(row pgx.Row) (*domain.Credential, error) {
	var (
		c          domain.Credential
		access     string
		refresh    string
		scopesJSON []byte
		expiresAt  *time.Time
	)
	if err := row.Scan(&c.ID, &c.GatewayID, &c.PrincipalSub, &c.Provider, &c.AccountRef,
		&access, &refresh, &scopesJSON, &expiresAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	var err error
	if c.AccessToken, err = r.cipher.Decrypt(access); err != nil {
		return nil, fmt.Errorf("%w: undecryptable access token for %s/%s: %v",
			domain.ErrNotFound, c.PrincipalSub, c.Provider, err)
	}
	if c.RefreshToken, err = r.cipher.Decrypt(refresh); err != nil {
		return nil, fmt.Errorf("%w: undecryptable refresh token for %s/%s: %v",
			domain.ErrNotFound, c.PrincipalSub, c.Provider, err)
	}
	if len(scopesJSON) > 0 {
		if err := json.Unmarshal(scopesJSON, &c.Scopes); err != nil {
			return nil, fmt.Errorf("vault repository: unmarshal scopes: %w", err)
		}
	}
	if expiresAt != nil {
		c.ExpiresAt = *expiresAt
	}
	return &c, nil
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
