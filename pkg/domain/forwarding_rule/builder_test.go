package forwarding_rule

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_Success(t *testing.T) {
	gatewayID := uuid.New()
	serviceID := uuid.New()

	rule, err := New(CreateParams{
		GatewayID: gatewayID,
		ServiceID: serviceID,
		Name:      "test-rule",
		Path:      "/api/v1",
		Methods:   domain.MethodsJSON{"GET", "POST"},
	})

	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, rule.ID)
	assert.Equal(t, gatewayID, rule.GatewayID)
	assert.Equal(t, serviceID, rule.ServiceID)
	assert.Equal(t, "test-rule", rule.Name)
	assert.Equal(t, "/api/v1", rule.Path)
	assert.Equal(t, domain.MethodsJSON{"GET", "POST"}, rule.Methods)
	assert.True(t, rule.Active)
	assert.False(t, rule.Public)
	assert.False(t, rule.CreatedAt.IsZero())
	assert.Equal(t, rule.CreatedAt, rule.UpdatedAt)
}

func TestNew_DefaultsToEndpointType(t *testing.T) {
	rule, err := New(CreateParams{
		GatewayID: uuid.New(),
		ServiceID: uuid.New(),
		Name:      "rule",
		Path:      "/api",
		Methods:   domain.MethodsJSON{"GET"},
	})

	require.NoError(t, err)
	assert.Equal(t, EndpointRuleType, rule.Type)
}

func TestNew_PreservesExplicitType(t *testing.T) {
	rule, err := New(CreateParams{
		GatewayID: uuid.New(),
		ServiceID: uuid.New(),
		Name:      "agent-rule",
		Path:      "/agent",
		Methods:   domain.MethodsJSON{"POST"},
		Type:      AgentRuleType,
	})

	require.NoError(t, err)
	assert.Equal(t, AgentRuleType, rule.Type)
}

func TestNew_WithOptionalFields(t *testing.T) {
	trustLens := &domain.TrustLensJSON{TeamID: "team-1"}
	sessionCfg := &SessionConfig{HeaderName: "X-Session"}

	rule, err := New(CreateParams{
		GatewayID:     uuid.New(),
		ServiceID:     uuid.New(),
		Name:          "full-rule",
		Path:          "/v1/chat",
		Paths:         domain.PathsJSON{"/v1/chat", "/v1/completions"},
		Methods:       domain.MethodsJSON{"POST"},
		Headers:       domain.HeadersJSON{"Content-Type": "application/json"},
		StripPath:     true,
		PreserveHost:  true,
		RetryAttempts: 3,
		TrustLens:     trustLens,
		SessionConfig: sessionCfg,
	})

	require.NoError(t, err)
	assert.Equal(t, "/v1/chat", rule.Path)
	assert.Equal(t, domain.PathsJSON{"/v1/chat", "/v1/completions"}, rule.Paths)
	assert.True(t, rule.StripPath)
	assert.True(t, rule.PreserveHost)
	assert.Equal(t, 3, rule.RetryAttempts)
	assert.Equal(t, "team-1", rule.TrustLens.TeamID)
	assert.Equal(t, "X-Session", rule.SessionConfig.HeaderName)
}

func TestNew_GeneratesUniqueIDs(t *testing.T) {
	params := CreateParams{
		GatewayID: uuid.New(),
		ServiceID: uuid.New(),
		Name:      "rule",
		Path:      "/api",
		Methods:   domain.MethodsJSON{"GET"},
	}

	r1, err := New(params)
	require.NoError(t, err)

	r2, err := New(params)
	require.NoError(t, err)

	assert.NotEqual(t, r1.ID, r2.ID)
}
