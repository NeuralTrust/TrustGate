package forwarding_rule

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validRule() *ForwardingRule {
	return &ForwardingRule{
		Path:      "/api/v1",
		ServiceID: uuid.New(),
		Methods:   []string{"POST"},
	}
}

func TestValidate_ValidMinimalRule(t *testing.T) {
	r := validRule()
	assert.NoError(t, r.Validate())
}

func TestValidate_PathRequired(t *testing.T) {
	r := validRule()
	r.Path = ""
	err := r.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path is required")
}

func TestValidate_ServiceIDRequired(t *testing.T) {
	r := validRule()
	r.ServiceID = uuid.Nil
	err := r.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service_id is required")
}

func TestValidate_MethodsRequired(t *testing.T) {
	r := validRule()
	r.Methods = nil
	err := r.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one HTTP method is required")
}

func TestValidate_InvalidHTTPMethod(t *testing.T) {
	r := validRule()
	r.Methods = []string{"GET", "INVALID"}
	err := r.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HTTP method: INVALID")
}

func TestValidate_AllValidHTTPMethods(t *testing.T) {
	r := validRule()
	r.Methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	assert.NoError(t, r.Validate())
}

func TestValidate_SessionConfig_NilIsValid(t *testing.T) {
	r := validRule()
	r.SessionConfig = nil
	assert.NoError(t, r.Validate())
}

func TestValidate_SessionConfig_BothEmpty_DefaultsToHeader(t *testing.T) {
	r := validRule()
	r.SessionConfig = &SessionConfig{}

	require.NoError(t, r.Validate())
	assert.Equal(t, "X-TG-SESSION-ID", r.SessionConfig.HeaderName)
	assert.Empty(t, r.SessionConfig.BodyParamName)
}

func TestValidate_SessionConfig_OnlyHeaderName(t *testing.T) {
	r := validRule()
	r.SessionConfig = &SessionConfig{HeaderName: "X-Custom-Session"}

	require.NoError(t, r.Validate())
	assert.Equal(t, "X-Custom-Session", r.SessionConfig.HeaderName)
	assert.Empty(t, r.SessionConfig.BodyParamName)
}

func TestValidate_SessionConfig_OnlyBodyParamName(t *testing.T) {
	r := validRule()
	r.SessionConfig = &SessionConfig{BodyParamName: "session_id"}

	require.NoError(t, r.Validate())
	assert.Empty(t, r.SessionConfig.HeaderName)
	assert.Equal(t, "session_id", r.SessionConfig.BodyParamName)
}

func TestValidate_SessionConfig_BothSet_MutuallyExclusive(t *testing.T) {
	r := validRule()
	r.SessionConfig = &SessionConfig{
		HeaderName:    "X-Session",
		BodyParamName: "session_id",
	}

	err := r.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}
