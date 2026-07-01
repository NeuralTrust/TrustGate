//go:build functional

package functional_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	vaultrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDBLessMCPVault_ConnectResolveRefreshOverRedis(t *testing.T) {
	defer Track(t, "DBLessMCPVault")()

	cipher, err := crypto.NewCipher("functional-vault-secret-key-1234567890")
	require.NoError(t, err)
	repo := vaultrepo.NewRedisRepository(redisDB, cipher)

	ctx := context.Background()
	gatewayID := ids.New[ids.GatewayKind]()
	principal := "user-" + gatewayID.String()
	provider := "github"

	connectCred, err := vaultdomain.NewCredential(
		gatewayID, principal, provider, "acct-github",
		"access-connect", "refresh-connect", []string{"repo"}, time.Now().Add(time.Hour).UTC(),
	)
	require.NoError(t, err)
	require.NoError(t, repo.Upsert(ctx, connectCred))

	resolved, err := repo.Find(ctx, gatewayID, principal, provider)
	require.NoError(t, err)
	assert.Equal(t, "access-connect", resolved.AccessToken)
	assert.Equal(t, "refresh-connect", resolved.RefreshToken)
	assert.Equal(t, "acct-github", resolved.AccountRef)

	key := "vault:" + gatewayID.String() + ":" + principal + ":" + provider
	raw, err := redisDB.Get(ctx, key).Result()
	require.NoError(t, err)
	assert.NotContains(t, raw, "access-connect", "raw redis value must not leak plaintext access token")
	assert.NotContains(t, raw, "refresh-connect", "raw redis value must not leak plaintext refresh token")

	var blob struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &blob))
	require.NotEqual(t, "access-connect", blob.AccessToken)
	decryptedAccess, err := cipher.Decrypt(blob.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "access-connect", decryptedAccess)

	refreshedCred, err := vaultdomain.NewCredential(
		gatewayID, principal, provider, "acct-github",
		"access-refreshed", "", []string{"repo"}, time.Now().Add(2*time.Hour).UTC(),
	)
	require.NoError(t, err)
	require.NoError(t, repo.Upsert(ctx, refreshedCred))

	afterRefresh, err := repo.Find(ctx, gatewayID, principal, provider)
	require.NoError(t, err)
	assert.Equal(t, "access-refreshed", afterRefresh.AccessToken, "refresh must persist the new access token")
	assert.Equal(t, "refresh-connect", afterRefresh.RefreshToken, "an empty refresh token must preserve the stored one")

	listed, err := repo.ListByPrincipal(ctx, gatewayID, principal)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, provider, listed[0].Provider)

	require.NoError(t, repo.Delete(ctx, gatewayID, principal, provider))
	_, err = repo.Find(ctx, gatewayID, principal, provider)
	require.True(t, errors.Is(err, vaultdomain.ErrNotFound),
		"a missing credential must surface ErrNotFound so the MCP flow degrades to re-consent")
	require.True(t, strings.Contains(err.Error(), "not found"))
}
