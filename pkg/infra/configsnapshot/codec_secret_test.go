package configsnapshot_test

import (
	"testing"
	"time"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodecPreservesRegistrySecrets(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	gwID := ids.New[ids.GatewayKind]()
	llm := registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gwID,
		Name:      "openai",
		Type:      registrydomain.TypeLLM,
		Enabled:   true,
		LLMTarget: &registrydomain.LLMTarget{
			Provider: "openai",
			Auth:     registrydomain.NewAPIKeyAuth("sk-llm-secret"),
		},
		CreatedAt: time.Unix(0, 0).UTC(),
	}
	mcp := registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gwID,
		Name:      "asana",
		Type:      registrydomain.TypeMCP,
		Enabled:   true,
		MCPTarget: &registrydomain.MCPTarget{
			URL: "https://mcp.example.com",
			Auth: &registrydomain.MCPAuth{
				Mode:   registrydomain.MCPAuthModeStatic,
				Header: "Authorization",
				Value:  "Bearer mcp-secret",
			},
		},
		CreatedAt: time.Unix(0, 0).UTC(),
	}

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{
		Registries: []registrydomain.Registry{llm, mcp},
	}))
	require.NoError(t, err)

	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	gotLLM, ok := snap.RegistryByID(llm.ID)
	require.True(t, ok)
	require.NotNil(t, gotLLM.LLMTarget)
	require.NotNil(t, gotLLM.LLMTarget.Auth)
	require.NotNil(t, gotLLM.LLMTarget.Auth.APIKey)
	assert.Equal(t, "sk-llm-secret", gotLLM.LLMTarget.Auth.APIKey.APIKey)

	gotMCP, ok := snap.RegistryByID(mcp.ID)
	require.True(t, ok)
	require.NotNil(t, gotMCP.MCPTarget)
	require.NotNil(t, gotMCP.MCPTarget.Auth)
	assert.Equal(t, "Bearer mcp-secret", gotMCP.MCPTarget.Auth.Value)
}

func TestCodecPreservesAuthKeyHash(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	auth := authdomain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: ids.New[ids.GatewayKind](),
		Type:      authdomain.TypeAPIKey,
		Enabled:   true,
		KeyHash:   "sha256-hash",
		CreatedAt: time.Unix(0, 0).UTC(),
	}

	raw, err := codec.Encode(readmodel.Build(readmodel.Data{Auths: []authdomain.Auth{auth}}))
	require.NoError(t, err)

	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	reraw, err := codec.Encode(snap)
	require.NoError(t, err)
	assert.Equal(t, raw, reraw, "decode then re-encode must be byte-identical with entities present")

	got, ok := snap.AuthByID(auth.ID)
	require.True(t, ok)
	assert.Equal(t, "sha256-hash", got.KeyHash, "KeyHash (json:\"-\") is carried as a dedicated proto field")

	byHash, ok := snap.AuthByAPIKeyHash("sha256-hash")
	require.True(t, ok)
	assert.Equal(t, auth.ID, byHash.ID)
}

func TestCodecRoundTripsCatalogProviderCode(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()

	data := readmodel.Data{
		Providers: []catalogdomain.Provider{{Code: "openai"}},
		CatalogModels: []readmodel.CatalogModel{
			{ProviderCode: "openai", Model: catalogdomain.Model{Slug: "gpt-4", DisplayName: "GPT-4", InputPrice: "1.5"}},
		},
	}
	raw, err := codec.Encode(readmodel.Build(data))
	require.NoError(t, err)

	snap, err := codec.Decode(raw)
	require.NoError(t, err)

	m, ok := snap.CatalogModelByProviderSlug("openai", "gpt-4")
	require.True(t, ok)
	assert.Equal(t, "GPT-4", m.DisplayName)
}
