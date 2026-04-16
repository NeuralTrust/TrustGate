package service

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Success(t *testing.T) {
	gatewayID := uuid.New()
	upstreamID := uuid.New()

	svc, err := New(CreateParams{
		GatewayID:   gatewayID,
		Name:        "my-service",
		Type:        TypeUpstream,
		Description: "test service",
		UpstreamID:  upstreamID,
		Tags:        []string{"v1"},
	})

	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, svc.ID)
	assert.Equal(t, gatewayID, svc.GatewayID)
	assert.Equal(t, "my-service", svc.Name)
	assert.Equal(t, TypeUpstream, svc.Type)
	assert.Equal(t, "test service", svc.Description)
	assert.Equal(t, upstreamID, svc.UpstreamID)
	assert.Equal(t, []string{"v1"}, []string(svc.Tags))
	assert.False(t, svc.CreatedAt.IsZero())
	assert.False(t, svc.UpdatedAt.IsZero())
	assert.Equal(t, svc.CreatedAt, svc.UpdatedAt)
}

func TestNew_EndpointType(t *testing.T) {
	svc, err := New(CreateParams{
		GatewayID: uuid.New(),
		Name:      "endpoint-svc",
		Type:      TypeEndpoint,
		Host:      "api.example.com",
		Port:      443,
		Protocol:  "https",
		Path:      "/v1",
	})

	require.NoError(t, err)
	assert.Equal(t, TypeEndpoint, svc.Type)
	assert.Equal(t, "api.example.com", svc.Host)
	assert.Equal(t, 443, svc.Port)
	assert.Equal(t, "https", svc.Protocol)
	assert.Equal(t, "/v1", svc.Path)
}

func TestNew_GeneratesUniqueIDs(t *testing.T) {
	params := CreateParams{
		GatewayID: uuid.New(),
		Name:      "svc",
		Type:      TypeUpstream,
	}

	s1, err := New(params)
	require.NoError(t, err)

	s2, err := New(params)
	require.NoError(t, err)

	assert.NotEqual(t, s1.ID, s2.ID)
}

func TestNew_WithHeadersAndCredentials(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer token"}
	creds := domain.CredentialsJSON{ApiKey: "secret"}

	svc, err := New(CreateParams{
		GatewayID:   uuid.New(),
		Name:        "full-svc",
		Type:        TypeEndpoint,
		Host:        "api.example.com",
		Port:        443,
		Protocol:    "https",
		Headers:     headers,
		Credentials: creds,
	})

	require.NoError(t, err)
	assert.Equal(t, headers, map[string]string(svc.Headers))
	assert.Equal(t, "secret", svc.Credentials.ApiKey)
}
