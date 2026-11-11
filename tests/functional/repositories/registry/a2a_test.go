//go:build functional

package registry_test

import (
	"context"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const a2aCard = `{"name":"Travel planner","supportedInterfaces":[{"url":"https://travel.example.com/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}`

func a2aRegistry(t *testing.T, gwID ids.GatewayID) *domain.Registry {
	t.Helper()
	target := &domain.A2ATarget{
		CardURL:  "https://travel.example.com",
		Headers:  map[string]string{"X-Tenant": headerValue},
		Auth:     &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "X-Api-Key", Value: staticValue},
		CardAuth: domain.A2ACardAuthSame,
	}
	target.Normalize()
	require.NoError(t, target.Pin("https://travel.example.com/.well-known/agent-card.json", []byte(a2aCard), time.Now()))
	reg, err := domain.NewA2ARegistry(gwID, "Travel planner", "", target)
	require.NoError(t, err)
	return reg
}

func TestRepository_A2ATargetRoundTrip(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agents")
	reg := a2aRegistry(t, gwID)
	require.NoError(t, r.Save(ctx, reg))

	var raw []byte
	require.NoError(t, conn.Pool.QueryRow(ctx, `SELECT a2a_target FROM registries WHERE id = $1`, reg.ID).Scan(&raw))
	assert.NotContains(t, string(raw), headerValue)
	assert.NotContains(t, string(raw), staticValue)

	got, err := r.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	require.NotNil(t, got.A2ATarget)
	assert.Equal(t, domain.TypeA2A, got.Type)
	assert.Nil(t, got.LLMTarget)
	assert.Equal(t, headerValue, got.A2ATarget.Headers["X-Tenant"])
	assert.Equal(t, staticValue, got.A2ATarget.Auth.Value)
	assert.Equal(t, reg.A2ATarget.CardDigest, got.A2ATarget.CardDigest)
	assert.Equal(t, domain.A2AVersion10, got.A2ATarget.ProtocolVersion)
	assert.JSONEq(t, a2aCard, string(got.A2ATarget.Card))
	assert.Equal(t, "https://travel.example.com/a2a", got.A2ATarget.Endpoint())

	got.A2ATarget.Headers["X-Tenant"] = "rotated"
	got.UpdatedAt = time.Now().UTC()
	require.NoError(t, r.Update(ctx, got))
	again, err := r.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	assert.Equal(t, "rotated", again.A2ATarget.Headers["X-Tenant"])
	assert.Equal(t, staticValue, again.A2ATarget.Auth.Value)
}

func TestRepository_A2AUnreadableSecretKeptOnUpdate(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agents-rotated-key")
	reg := a2aRegistry(t, gwID)
	require.NoError(t, r.Save(ctx, reg))

	var before []byte
	require.NoError(t, conn.Pool.QueryRow(ctx, `SELECT a2a_target FROM registries WHERE id = $1`, reg.ID).Scan(&before))

	otherSealer, err := crypto.NewFieldSealer("another-functional-secret-0123456789abcdef", crypto.RegistrySecretsPurpose)
	require.NoError(t, err)
	cipher, err := crypto.NewCipher(testSecretKey)
	require.NoError(t, err)
	other := repo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn), repo.WithFieldSealer(otherSealer, true))

	got, err := other.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	assert.Empty(t, got.A2ATarget.Auth.Value)
	assert.True(t, got.A2ATarget.Auth.SecretUnreadable)

	got.Name = "Renamed"
	require.NoError(t, other.Update(ctx, got))

	back, err := r.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	assert.Equal(t, "Renamed", back.Name)
	assert.Equal(t, staticValue, back.A2ATarget.Auth.Value)
	assert.Equal(t, headerValue, back.A2ATarget.Headers["X-Tenant"])
}

func TestRepository_A2APlainWhenEncryptionOff(t *testing.T) {
	_, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agents-plain")
	cipher, err := crypto.NewCipher(testSecretKey)
	require.NoError(t, err)
	sealer, err := crypto.NewFieldSealer(testSecretKey, crypto.RegistrySecretsPurpose)
	require.NoError(t, err)
	plain := repo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn), repo.WithFieldSealer(sealer, false))

	reg := a2aRegistry(t, gwID)
	require.NoError(t, plain.Save(ctx, reg))
	var raw []byte
	require.NoError(t, conn.Pool.QueryRow(ctx, `SELECT a2a_target FROM registries WHERE id = $1`, reg.ID).Scan(&raw))
	assert.Contains(t, string(raw), staticValue)

	got, err := plain.FindByID(ctx, reg.ID)
	require.NoError(t, err)
	assert.Equal(t, staticValue, got.A2ATarget.Auth.Value)
}
