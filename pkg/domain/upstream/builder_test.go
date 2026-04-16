package upstream

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Success(t *testing.T) {
	params := CreateParams{
		GatewayID: uuid.New(),
		Name:      "test-upstream",
		Algorithm: "round-robin",
		Targets: []Target{
			{ID: "t1", Host: "example.com", Port: 443, Protocol: "https", Weight: 100},
		},
		Tags: []string{"prod"},
	}

	u, err := New(params)

	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, u.ID)
	assert.Equal(t, params.GatewayID, u.GatewayID)
	assert.Equal(t, "test-upstream", u.Name)
	assert.Equal(t, "round-robin", u.Algorithm)
	assert.Len(t, u.Targets, 1)
	assert.Equal(t, "t1", u.Targets[0].ID)
	assert.Equal(t, []string{"prod"}, []string(u.Tags))
	assert.False(t, u.CreatedAt.IsZero())
	assert.False(t, u.UpdatedAt.IsZero())
	assert.Equal(t, u.CreatedAt, u.UpdatedAt)
}

func TestNew_WithAllOptionalFields(t *testing.T) {
	embedding := NewEmbeddingConfig("openai", "text-embedding-3-small", domain.CredentialsJSON{ApiKey: "key"})
	hc := NewHealthCheck(false, "/health", nil, 3, 30)
	ws := NewWebsocketConfig(true, false, "30s", "60s", "10s", 1024, 1024)
	proxy := NewProxy("proxy.example.com", "8080", "https")

	params := CreateParams{
		GatewayID:       uuid.New(),
		Name:            "full-upstream",
		Algorithm:       "semantic",
		Targets:         []Target{{ID: "t1", Provider: "openai", Description: "desc"}},
		EmbeddingConfig: embedding,
		HealthChecks:    hc,
		Websocket:       ws,
		Proxy:           proxy,
	}

	u, err := New(params)

	require.NoError(t, err)
	assert.NotNil(t, u.EmbeddingConfig)
	assert.Equal(t, "openai", u.EmbeddingConfig.Provider)
	assert.NotNil(t, u.HealthChecks)
	assert.Equal(t, "/health", u.HealthChecks.Path)
	assert.NotNil(t, u.Websocket)
	assert.True(t, u.Websocket.EnableDirectCommunication)
	assert.NotNil(t, u.Proxy)
	assert.Equal(t, "https", u.Proxy.Protocol)
}

func TestNew_GeneratesUniqueIDs(t *testing.T) {
	params := CreateParams{
		GatewayID: uuid.New(),
		Name:      "test",
		Algorithm: "round-robin",
	}

	u1, err := New(params)
	require.NoError(t, err)

	u2, err := New(params)
	require.NoError(t, err)

	assert.NotEqual(t, u1.ID, u2.ID)
}

func TestNewProxy_DefaultProtocol(t *testing.T) {
	p := NewProxy("host", "8080", "")
	assert.Equal(t, "http", p.Protocol)
}

func TestNewProxy_CustomProtocol(t *testing.T) {
	p := NewProxy("host", "443", "https")
	assert.Equal(t, "https", p.Protocol)
}

func TestNewEmbeddingConfig(t *testing.T) {
	creds := domain.CredentialsJSON{ApiKey: "test-key"}
	ec := NewEmbeddingConfig("openai", "text-embedding-3-small", creds)

	assert.Equal(t, "openai", ec.Provider)
	assert.Equal(t, "text-embedding-3-small", ec.Model)
	assert.Equal(t, "test-key", ec.Credentials.ApiKey)
}

func TestNewHealthCheck(t *testing.T) {
	headers := map[string]string{"Accept": "application/json"}
	hc := NewHealthCheck(true, "/healthz", headers, 5, 60)

	assert.True(t, hc.Passive)
	assert.Equal(t, "/healthz", hc.Path)
	assert.Equal(t, headers, map[string]string(hc.Headers))
	assert.Equal(t, 5, hc.Threshold)
	assert.Equal(t, 60, hc.Interval)
}

func TestNewWebsocketConfig(t *testing.T) {
	ws := NewWebsocketConfig(true, true, "30s", "60s", "10s", 2048, 4096)

	assert.True(t, ws.EnableDirectCommunication)
	assert.True(t, ws.ReturnErrorDetails)
	assert.Equal(t, "30s", ws.PingPeriod)
	assert.Equal(t, "60s", ws.PongWait)
	assert.Equal(t, "10s", ws.HandshakeTimeout)
	assert.Equal(t, 2048, ws.ReadBufferSize)
	assert.Equal(t, 4096, ws.WriteBufferSize)
}

func TestNewTarget(t *testing.T) {
	target := NewTarget(
		"t1", 100, []string{"gpu"}, map[string]string{"X-Custom": "val"},
		"/v1", "api.example.com", 443, "https",
		"openai", map[string]any{"api": "completions"}, ModelsJSON{"gpt-4"},
		"gpt-4", "main backend",
		true, false, domain.CredentialsJSON{ApiKey: "key"},
	)

	assert.Equal(t, "t1", target.ID)
	assert.Equal(t, 100, target.Weight)
	assert.Equal(t, "api.example.com", target.Host)
	assert.Equal(t, 443, target.Port)
	assert.Equal(t, "openai", target.Provider)
	assert.Equal(t, "gpt-4", target.DefaultModel)
	assert.True(t, target.Stream)
	assert.False(t, target.InsecureSSL)
}

func TestNewOAuth2Auth(t *testing.T) {
	config := &TargetOAuthConfig{
		TokenURL:  "https://auth.example.com/token",
		GrantType: "client_credentials",
		ClientID:  "my-client",
	}

	auth := NewOAuth2Auth(config)

	assert.Equal(t, AuthTypeOAuth2, auth.Type)
	assert.NotNil(t, auth.OAuth)
	assert.Equal(t, "https://auth.example.com/token", auth.OAuth.TokenURL)
	assert.Nil(t, auth.GCPServiceAccount)
}

func TestNewGCPServiceAccountAuth(t *testing.T) {
	auth := NewGCPServiceAccountAuth("encrypted-sa-data")

	assert.Equal(t, AuthTypeGCPServiceAccount, auth.Type)
	assert.Nil(t, auth.OAuth)
	require.NotNil(t, auth.GCPServiceAccount)
	assert.Equal(t, "encrypted-sa-data", *auth.GCPServiceAccount)
}
