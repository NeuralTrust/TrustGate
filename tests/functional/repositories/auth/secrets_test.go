//go:build functional

package auth_test

import (
	"context"
	"encoding/json"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/auth"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/stretchr/testify/require"
)

func oauth2AuthWithSecrets(t *testing.T, gwID ids.GatewayID, name string) *domain.Auth {
	t.Helper()
	a, err := domain.NewAuth(gwID, name, domain.TypeOAuth2, true, domain.Config{OAuth2: &domain.OAuth2Config{
		Issuer:               "https://issuer.example.com",
		Audiences:            []string{"gateway"},
		JWKSURL:              "https://issuer.example.com/.well-known/jwks.json",
		ClientID:             "login",
		ClientSecret:         "login-secret-value",
		ExchangeClientID:     "exchange",
		ExchangeClientSecret: "exchange-secret-value",
	}})
	require.NoError(t, err)
	return a
}

func storedConfig(t *testing.T, conn *database.Connection, id ids.AuthID) (string, domain.Config) {
	t.Helper()
	var raw []byte
	require.NoError(t, conn.Pool.QueryRow(context.Background(), `SELECT config FROM auths WHERE id = $1`, id).Scan(&raw))
	var cfg domain.Config
	require.NoError(t, json.Unmarshal(raw, &cfg))
	return string(raw), cfg
}

func TestRepository_ClientSecretsStoredEncrypted(t *testing.T) {
	r, gw, conn := setupRepoConn(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "sealed")

	a := oauth2AuthWithSecrets(t, gwID, "idp")
	require.NoError(t, r.Save(ctx, a))
	require.Equal(t, "login-secret-value", a.Config.OAuth2.ClientSecret, "Save must not modify the auth")

	raw, stored := storedConfig(t, conn, a.ID)
	require.NotContains(t, raw, "login-secret-value")
	require.NotContains(t, raw, "exchange-secret-value")
	require.True(t, crypto.IsSealed(stored.OAuth2.ClientSecret))
	require.True(t, crypto.IsSealed(stored.OAuth2.ExchangeClientSecret))

	got, err := r.FindByID(ctx, a.ID)
	require.NoError(t, err)
	require.Equal(t, "login-secret-value", got.Config.OAuth2.ClientSecret)
	require.Equal(t, "exchange-secret-value", got.Config.OAuth2.ExchangeClientSecret)

	got.Name = "renamed"
	require.NoError(t, r.Update(ctx, got))
	reread, err := r.FindByID(ctx, a.ID)
	require.NoError(t, err)
	require.Equal(t, "login-secret-value", reread.Config.OAuth2.ClientSecret, "an update must encrypt once, never twice")
}

func TestRepository_SealStoredSecretsIsIdempotent(t *testing.T) {
	r, gw, conn := setupRepoConn(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "backfill")

	legacy := oauth2AuthWithSecrets(t, gwID, "legacy")
	current := oauth2AuthWithSecrets(t, gwID, "current")
	require.NoError(t, r.Save(ctx, legacy))
	require.NoError(t, r.Save(ctx, current))
	plain, err := json.Marshal(legacy.Config)
	require.NoError(t, err)
	_, err = conn.Pool.Exec(ctx, `UPDATE auths SET config = $2 WHERE id = $1`, legacy.ID, plain)
	require.NoError(t, err)

	got, err := r.FindByID(ctx, legacy.ID)
	require.NoError(t, err)
	require.Equal(t, "login-secret-value", got.Config.OAuth2.ClientSecret, "a legacy row still reads")

	n, failed, err := r.SealStoredSecrets(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Zero(t, failed)
	raw, stored := storedConfig(t, conn, legacy.ID)
	require.NotContains(t, raw, "login-secret-value")
	require.True(t, crypto.IsSealed(stored.OAuth2.ClientSecret))

	got, err = r.FindByID(ctx, legacy.ID)
	require.NoError(t, err)
	require.Equal(t, "exchange-secret-value", got.Config.OAuth2.ExchangeClientSecret)

	n, failed, err = r.SealStoredSecrets(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Zero(t, failed)
}

func repoWithKey(t *testing.T, conn *database.Connection, secret string, encryptWrites bool) *repo.Repository {
	t.Helper()
	sealer, err := crypto.NewFieldSealer(secret, crypto.RegistrySecretsPurpose)
	require.NoError(t, err)
	return repo.NewRepository(conn, outboxrepo.NewRepository(conn), repo.WithFieldSealer(sealer, encryptWrites))
}

func TestRepository_EncryptionOffWritesPlainAndReadsEncrypted(t *testing.T) {
	sealing, gw, conn := setupRepoConn(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "flag-off")
	plain := repoWithKey(t, conn, testSecretKey, false)

	written := oauth2AuthWithSecrets(t, gwID, "written-plain")
	require.NoError(t, plain.Save(ctx, written))
	raw, _ := storedConfig(t, conn, written.ID)
	require.Contains(t, raw, "login-secret-value")

	sealed := oauth2AuthWithSecrets(t, gwID, "written-sealed")
	require.NoError(t, sealing.Save(ctx, sealed))
	got, err := plain.FindByID(ctx, sealed.ID)
	require.NoError(t, err)
	require.Equal(t, "login-secret-value", got.Config.OAuth2.ClientSecret)

	_, _, err = plain.SealStoredSecrets(ctx)
	require.Error(t, err, "the backfill needs encrypted writes enabled")
}

func TestRepository_UnreadableClientSecretIsReturnedEmpty(t *testing.T) {
	r, gw, conn := setupRepoConn(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "unreadable")

	broken := oauth2AuthWithSecrets(t, gwID, "broken")
	healthy := oauth2AuthWithSecrets(t, gwID, "healthy")
	require.NoError(t, r.Save(ctx, broken))
	require.NoError(t, r.Save(ctx, healthy))
	require.NoError(t, repoWithKey(t, conn, "another-functional-secret-0123456789", true).Update(ctx, broken))

	got, err := r.FindByID(ctx, broken.ID)
	require.NoError(t, err)
	require.Empty(t, got.Config.OAuth2.ClientSecret)
	require.Equal(t, "login", got.Config.OAuth2.ClientID)

	list, _, err := r.List(ctx, domain.ListFilter{GatewayID: gwID})
	require.NoError(t, err)
	require.Len(t, list, 2)
}

func TestRepository_UpdateKeepsClientSecretsItCannotDecrypt(t *testing.T) {
	keyA, gw, conn := setupRepoConn(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "keep")
	keyB := repoWithKey(t, conn, "another-functional-secret-0123456789", true)

	a := oauth2AuthWithSecrets(t, gwID, "idp")
	require.NoError(t, keyA.Save(ctx, a))
	before, beforeCfg := storedConfig(t, conn, a.ID)

	t.Run("name only", func(t *testing.T) {
		got, err := keyB.FindByID(ctx, a.ID)
		require.NoError(t, err)
		require.Empty(t, got.Config.OAuth2.ExchangeClientSecret)
		require.True(t, got.Config.OAuth2.ExchangeSecretUnreadable)
		got.Name = "renamed"
		require.NoError(t, got.Config.Validate(got.Type), "an unreadable secret must not block unrelated edits")
		require.NoError(t, keyB.Update(ctx, got))
		after, _ := storedConfig(t, conn, a.ID)
		require.JSONEq(t, before, after)
	})

	t.Run("masked echo", func(t *testing.T) {
		prev, err := keyB.FindByID(ctx, a.ID)
		require.NoError(t, err)
		incoming := domain.Config{OAuth2: &domain.OAuth2Config{
			Issuer: prev.Config.OAuth2.Issuer, Audiences: prev.Config.OAuth2.Audiences, JWKSURL: prev.Config.OAuth2.JWKSURL,
			ClientID: "login", ClientSecret: "",
			ExchangeClientID: "exchange", ExchangeClientSecret: "***",
		}}
		incoming.ResolveSecretsFrom(prev.Config)
		require.NoError(t, incoming.Validate(prev.Type))
		prev.Config = incoming
		require.NoError(t, keyB.Update(ctx, prev))
		after, _ := storedConfig(t, conn, a.ID)
		require.JSONEq(t, before, after)

		readable, err := keyA.FindByID(ctx, a.ID)
		require.NoError(t, err)
		require.Equal(t, "login-secret-value", readable.Config.OAuth2.ClientSecret)
		require.Equal(t, "exchange-secret-value", readable.Config.OAuth2.ExchangeClientSecret)
	})

	t.Run("new value replaces", func(t *testing.T) {
		got, err := keyB.FindByID(ctx, a.ID)
		require.NoError(t, err)
		got.Config.OAuth2.ExchangeClientSecret = "replaced-secret"
		got.Config.OAuth2.ExchangeSecretUnreadable = false
		require.NoError(t, keyB.Update(ctx, got))
		_, after := storedConfig(t, conn, a.ID)
		require.NotEqual(t, beforeCfg.OAuth2.ExchangeClientSecret, after.OAuth2.ExchangeClientSecret)
		require.Equal(t, beforeCfg.OAuth2.ClientSecret, after.OAuth2.ClientSecret, "the untouched secret is kept")
		reread, err := keyB.FindByID(ctx, a.ID)
		require.NoError(t, err)
		require.Equal(t, "replaced-secret", reread.Config.OAuth2.ExchangeClientSecret)
	})

	t.Run("cleared client id drops its secret", func(t *testing.T) {
		got, err := keyB.FindByID(ctx, a.ID)
		require.NoError(t, err)
		got.Config.OAuth2.ClientID = ""
		require.NoError(t, keyB.Update(ctx, got))
		_, after := storedConfig(t, conn, a.ID)
		require.Empty(t, after.OAuth2.ClientSecret)
	})
}

func TestRepository_StaleUnreadableReadDoesNotBlankAReEnteredSecret(t *testing.T) {
	keyA, gw, conn := setupRepoConn(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "race")
	keyB := repoWithKey(t, conn, "another-functional-secret-0123456789", true)

	a := oauth2AuthWithSecrets(t, gwID, "idp")
	require.NoError(t, keyA.Save(ctx, a))

	stale, err := keyB.FindByID(ctx, a.ID)
	require.NoError(t, err)
	require.True(t, stale.Config.OAuth2.ClientSecretUnreadable)
	require.True(t, stale.Config.OAuth2.ExchangeSecretUnreadable)

	reentry, err := keyB.FindByID(ctx, a.ID)
	require.NoError(t, err)
	reentry.Config.OAuth2.ClientSecret = "re-entered-login"
	reentry.Config.OAuth2.ExchangeClientSecret = "re-entered-exchange"
	reentry.Config.OAuth2.ClientSecretUnreadable = false
	reentry.Config.OAuth2.ExchangeSecretUnreadable = false
	require.NoError(t, keyB.Update(ctx, reentry))

	stale.Name = "renamed-from-a-stale-read"
	require.NoError(t, keyB.Update(ctx, stale))

	got, err := keyB.FindByID(ctx, a.ID)
	require.NoError(t, err)
	require.Equal(t, "re-entered-login", got.Config.OAuth2.ClientSecret)
	require.Equal(t, "re-entered-exchange", got.Config.OAuth2.ExchangeClientSecret)
}
