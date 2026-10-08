//go:build functional

package registry_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"github.com/stretchr/testify/require"
)

const (
	headerValue  = "header-value-123"
	staticValue  = "Bearer static-value-123"
	clientSecret = "client-secret-value-123"
)

func staticMCPRegistry(t *testing.T, gwID ids.GatewayID, name string) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(gwID, name, "", &domain.MCPTarget{
		URL:     "https://mcp.example.com/mcp",
		Headers: map[string]string{"X-Api-Key": headerValue},
		Auth:    &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: staticValue},
	})
	require.NoError(t, err)
	return reg
}

func sharedOAuthMCPRegistry(t *testing.T, gwID ids.GatewayID, name string) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(gwID, name, "", &domain.MCPTarget{
		Code: "com.google.workspace/gmail",
		URL:  "https://gmailmcp.googleapis.com/mcp/v1",
		Auth: &domain.MCPAuth{
			Mode: domain.MCPAuthModeForwarded, Provider: "com.google.workspace/gmail",
			Registration: domain.RegistrationManual, ClientID: "nt-client", ClientSecret: clientSecret,
		},
	})
	require.NoError(t, err)
	return reg
}

func storedMCPTarget(t *testing.T, conn *database.Connection, id ids.RegistryID) (string, domain.MCPTarget) {
	t.Helper()
	var raw []byte
	err := conn.Pool.QueryRow(context.Background(), `SELECT mcp_target FROM registries WHERE id = $1`, id).Scan(&raw)
	require.NoError(t, err)
	var target domain.MCPTarget
	require.NoError(t, json.Unmarshal(raw, &target))
	return string(raw), target
}

// writeLegacyMCPTarget stores target the way rows were written before field
// encryption existed.
func writeLegacyMCPTarget(t *testing.T, conn *database.Connection, id ids.RegistryID, target *domain.MCPTarget) {
	t.Helper()
	raw, err := json.Marshal(target)
	require.NoError(t, err)
	_, err = conn.Pool.Exec(context.Background(), `UPDATE registries SET mcp_target = $2 WHERE id = $1`, id, raw)
	require.NoError(t, err)
}

func requireSealed(t *testing.T, values ...string) {
	t.Helper()
	for _, v := range values {
		require.True(t, strings.HasPrefix(v, crypto.SealedPrefix), "stored value %q is not encrypted", v)
	}
}

func TestRepository_MCPTargetCredentialsStoredEncrypted(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "sealed")

	reg := staticMCPRegistry(t, gwID, "static")
	require.NoError(t, r.Save(ctx, reg))
	require.Equal(t, headerValue, reg.MCPTarget.Headers["X-Api-Key"], "Save must not modify the registry")

	raw, stored := storedMCPTarget(t, conn, reg.ID)
	require.NotContains(t, raw, headerValue)
	require.NotContains(t, raw, "static-value-123")
	requireSealed(t, stored.Headers["X-Api-Key"], stored.Auth.Value)
	require.Equal(t, "Authorization", stored.Auth.Header)

	got, err := r.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	require.Equal(t, headerValue, got.MCPTarget.Headers["X-Api-Key"])
	require.Equal(t, staticValue, got.MCPTarget.Auth.Value)

	got.Description = "edited"
	require.NoError(t, r.Update(ctx, got))
	_, again := storedMCPTarget(t, conn, reg.ID)
	requireSealed(t, again.Headers["X-Api-Key"], again.Auth.Value)
	reread, err := r.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	require.Equal(t, staticValue, reread.MCPTarget.Auth.Value, "an update must encrypt once, never twice")
}

func TestRepository_LegacyPlainMCPTargetStillReads(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "legacy")

	reg := staticMCPRegistry(t, gwID, "legacy")
	require.NoError(t, r.Save(ctx, reg))
	writeLegacyMCPTarget(t, conn, reg.ID, reg.MCPTarget)

	list, _, err := r.List(ctx, domain.ListFilter{GatewayID: gwID})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, headerValue, list[0].MCPTarget.Headers["X-Api-Key"])
	require.Equal(t, staticValue, list[0].MCPTarget.Auth.Value)
}

func TestRepository_RewriteMCPTargetsIsIdempotent(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "backfill")

	static := staticMCPRegistry(t, gwID, "static")
	shared := sharedOAuthMCPRegistry(t, gwID, "gmail")
	sealedAlready := staticMCPRegistry(t, gwID, "current")
	for _, reg := range []*domain.Registry{static, shared, sealedAlready} {
		require.NoError(t, r.Save(ctx, reg))
	}
	writeLegacyMCPTarget(t, conn, static.ID, static.MCPTarget)
	writeLegacyMCPTarget(t, conn, shared.ID, shared.MCPTarget)

	clearShared := func(t *domain.MCPTarget) bool {
		if t.Code != "com.google.workspace/gmail" || t.Auth == nil || t.Auth.ClientSecret == "" {
			return false
		}
		t.Auth.ClientSecret = ""
		return true
	}

	markers := outboxCount(t, conn)
	report, err := r.RewriteMCPTargets(ctx, clearShared)
	require.NoError(t, err)
	require.Equal(t, domain.SecretsRewriteReport{Scanned: 3, Encrypted: 2, Fixed: 1}, report)
	require.Equal(t, markers+1, outboxCount(t, conn), "only a changed target records a snapshot marker")

	_, stored := storedMCPTarget(t, conn, static.ID)
	requireSealed(t, stored.Headers["X-Api-Key"], stored.Auth.Value)
	raw, storedShared := storedMCPTarget(t, conn, shared.ID)
	require.NotContains(t, raw, clientSecret)
	require.Empty(t, storedShared.Auth.ClientSecret)
	require.Equal(t, "nt-client", storedShared.Auth.ClientID)

	got, err := r.FindByID(ctx, static.ID)
	require.NoError(t, err)
	require.Equal(t, staticValue, got.MCPTarget.Auth.Value)

	var wg sync.WaitGroup
	results := make([]domain.SecretsRewriteReport, 3)
	errs := make([]error, 3)
	for i := range results {
		wg.Go(func() {
			results[i], errs[i] = r.RewriteMCPTargets(ctx, clearShared)
		})
	}
	wg.Wait()
	for i := range results {
		require.NoError(t, errs[i])
		require.Equal(t, domain.SecretsRewriteReport{Scanned: 3}, results[i], "a rerun must find nothing left to do")
	}
	require.Equal(t, markers+1, outboxCount(t, conn))
}

func setupRepoWithKey(t *testing.T, conn *database.Connection, secret string, encryptWrites bool) *repo.Repository {
	t.Helper()
	sealer, err := crypto.NewFieldSealer(secret, crypto.RegistrySecretsPurpose)
	require.NoError(t, err)
	cipher, err := crypto.NewCipher(testSecretKey)
	require.NoError(t, err)
	return repo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn), repo.WithFieldSealer(sealer, encryptWrites))
}

func TestRepository_EncryptionOffWritesPlainAndReadsEncrypted(t *testing.T) {
	sealing, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "flag-off")
	plain := setupRepoWithKey(t, conn, testSecretKey, false)

	written := staticMCPRegistry(t, gwID, "written-plain")
	require.NoError(t, plain.Save(ctx, written))
	raw, _ := storedMCPTarget(t, conn, written.ID)
	require.Contains(t, raw, headerValue)
	require.NotContains(t, raw, crypto.SealedPrefix)

	sealed := staticMCPRegistry(t, gwID, "written-sealed")
	require.NoError(t, sealing.Save(ctx, sealed))
	got, err := plain.FindByID(ctx, sealed.ID)
	require.NoError(t, err)
	require.Equal(t, staticValue, got.MCPTarget.Auth.Value, "every read path decrypts enc:v1 values")

	_, err = plain.RewriteMCPTargets(ctx, nil)
	require.Error(t, err, "the backfill needs encrypted writes enabled")
}

func TestRepository_UnreadableCredentialIsReturnedEmpty(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "unreadable")

	broken := staticMCPRegistry(t, gwID, "broken")
	healthy := staticMCPRegistry(t, gwID, "healthy")
	require.NoError(t, r.Save(ctx, broken))
	require.NoError(t, r.Save(ctx, healthy))
	otherKey := setupRepoWithKey(t, conn, "another-functional-secret-0123456789", true)
	require.NoError(t, otherKey.Update(ctx, broken))

	got, err := r.FindByID(ctx, broken.ID)
	require.NoError(t, err)
	require.Empty(t, got.MCPTarget.Auth.Value)
	require.Empty(t, got.MCPTarget.Headers["X-Api-Key"])
	require.Equal(t, "Authorization", got.MCPTarget.Auth.Header)

	list, total, err := r.List(ctx, domain.ListFilter{GatewayID: gwID})
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, list, 2)
	byName := map[string]*domain.Registry{}
	for _, reg := range list {
		byName[reg.Name] = reg
	}
	require.Empty(t, byName["broken"].MCPTarget.Auth.Value)
	require.Equal(t, staticValue, byName["healthy"].MCPTarget.Auth.Value)

	report, err := r.RewriteMCPTargets(ctx, func(*domain.MCPTarget) bool { return true })
	require.NoError(t, err)
	require.Equal(t, 1, report.Failed, "a row that does not decrypt is skipped, not rewritten")
	require.Equal(t, 1, report.Fixed, "the pass carries on past it")
	reread, err := otherKey.FindByID(ctx, broken.ID)
	require.NoError(t, err)
	require.Equal(t, staticValue, reread.MCPTarget.Auth.Value, "the skipped row still opens under its key")
}

func TestRepository_SealedValueIsBoundToItsRow(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "bound")

	source := staticMCPRegistry(t, gwID, "source")
	target := staticMCPRegistry(t, gwID, "target")
	require.NoError(t, r.Save(ctx, source))
	require.NoError(t, r.Save(ctx, target))
	_, err := conn.Pool.Exec(ctx,
		`UPDATE registries SET mcp_target = (SELECT mcp_target FROM registries WHERE id = $1) WHERE id = $2`,
		source.ID, target.ID)
	require.NoError(t, err)

	got, err := r.FindByID(ctx, target.ID)
	require.NoError(t, err)
	require.Empty(t, got.MCPTarget.Auth.Value, "a value copied from another row does not open")
}

func TestRepository_UpdateKeepsCredentialsItCannotDecrypt(t *testing.T) {
	keyA, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "keep")
	keyB := setupRepoWithKey(t, conn, "another-functional-secret-0123456789", true)

	reg := staticMCPRegistry(t, gwID, "static")
	require.NoError(t, keyA.Save(ctx, reg))
	before, beforeTarget := storedMCPTarget(t, conn, reg.ID)

	t.Run("name only", func(t *testing.T) {
		got, err := keyB.FindByID(ctx, reg.ID)
		require.NoError(t, err)
		require.Empty(t, got.MCPTarget.Auth.Value)
		require.True(t, got.MCPTarget.Auth.SecretUnreadable)
		got.Name = "renamed"
		require.NoError(t, got.Validate(), "an unreadable credential must not block unrelated edits")
		require.NoError(t, keyB.Update(ctx, got))
		after, _ := storedMCPTarget(t, conn, reg.ID)
		require.JSONEq(t, before, after)
	})

	t.Run("masked echo", func(t *testing.T) {
		prev, err := keyB.FindByID(ctx, reg.ID)
		require.NoError(t, err)
		incoming := &domain.MCPTarget{
			URL:     prev.MCPTarget.URL,
			Headers: map[string]string{"X-Api-Key": "***"},
			Auth:    &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "***"},
		}
		incoming.ResolveSecretsFrom(prev.MCPTarget)
		prev.MCPTarget = incoming
		require.NoError(t, prev.Validate())
		require.NoError(t, keyB.Update(ctx, prev))
		after, _ := storedMCPTarget(t, conn, reg.ID)
		require.JSONEq(t, before, after)

		readable, err := keyA.FindByID(ctx, reg.ID)
		require.NoError(t, err)
		require.Equal(t, staticValue, readable.MCPTarget.Auth.Value)
		require.Equal(t, headerValue, readable.MCPTarget.Headers["X-Api-Key"])
	})

	t.Run("new value replaces", func(t *testing.T) {
		got, err := keyB.FindByID(ctx, reg.ID)
		require.NoError(t, err)
		got.MCPTarget.Auth.Value = "Bearer replaced"
		got.MCPTarget.Auth.SecretUnreadable = false
		got.MCPTarget.Headers["X-Api-Key"] = "replaced-header"
		require.NoError(t, got.Validate())
		require.NoError(t, keyB.Update(ctx, got))
		_, after := storedMCPTarget(t, conn, reg.ID)
		require.NotEqual(t, beforeTarget.Auth.Value, after.Auth.Value)
		reread, err := keyB.FindByID(ctx, reg.ID)
		require.NoError(t, err)
		require.Equal(t, "Bearer replaced", reread.MCPTarget.Auth.Value)
		require.Equal(t, "replaced-header", reread.MCPTarget.Headers["X-Api-Key"])
		require.False(t, reread.MCPTarget.Auth.SecretUnreadable)
	})
}

func TestRepository_UpdateWithEncryptionOffKeepsCredentialsItCannotDecrypt(t *testing.T) {
	sealing, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "keep-off")
	noKey := repo.NewRepository(conn, nil, outboxrepo.NewRepository(conn))

	reg := staticMCPRegistry(t, gwID, "static")
	require.NoError(t, sealing.Save(ctx, reg))
	before, _ := storedMCPTarget(t, conn, reg.ID)

	got, err := noKey.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	got.Description = "edited"
	require.NoError(t, noKey.Update(ctx, got))
	after, _ := storedMCPTarget(t, conn, reg.ID)
	require.JSONEq(t, before, after)
}

func TestRepository_UpdateDropsCredentialWhenAuthModeChanges(t *testing.T) {
	keyA, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "mode")
	keyB := setupRepoWithKey(t, conn, "another-functional-secret-0123456789", true)

	reg := staticMCPRegistry(t, gwID, "static")
	require.NoError(t, keyA.Save(ctx, reg))
	got, err := keyB.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	got.MCPTarget.Auth = &domain.MCPAuth{Mode: domain.MCPAuthModeNone}
	require.NoError(t, keyB.Update(ctx, got))
	_, stored := storedMCPTarget(t, conn, reg.ID)
	require.Empty(t, stored.Auth.Value)
}

func TestRepository_StaleUnreadableReadDoesNotBlankAReEnteredCredential(t *testing.T) {
	keyA, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "race")
	keyB := setupRepoWithKey(t, conn, "another-functional-secret-0123456789", true)

	reg := staticMCPRegistry(t, gwID, "static")
	require.NoError(t, keyA.Save(ctx, reg))

	stale, err := keyB.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	require.True(t, stale.MCPTarget.Auth.SecretUnreadable)
	require.Equal(t, []string{"X-Api-Key"}, stale.MCPTarget.UnreadableHeaders)

	reentry, err := keyB.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	reentry.MCPTarget.Auth.Value = "Bearer re-entered"
	reentry.MCPTarget.Auth.SecretUnreadable = false
	reentry.MCPTarget.Headers["X-Api-Key"] = "re-entered-header"
	reentry.MCPTarget.UnreadableHeaders = nil
	require.NoError(t, keyB.Update(ctx, reentry))

	stale.Name = "renamed-from-a-stale-read"
	require.NoError(t, stale.Validate())
	require.NoError(t, keyB.Update(ctx, stale))

	got, err := keyB.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	require.Equal(t, "renamed-from-a-stale-read", got.Name)
	require.Equal(t, "Bearer re-entered", got.MCPTarget.Auth.Value, "the re-entered value survives the stale update")
	require.Equal(t, "re-entered-header", got.MCPTarget.Headers["X-Api-Key"])
	require.False(t, got.MCPTarget.Auth.SecretUnreadable)
}
