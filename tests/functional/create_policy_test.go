//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePolicy_Success(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw")})

	name := uniqueName("pol-ok")
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(name))

	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, name, body["name"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.NotEmpty(t, body["id"])
	assert.NotEmpty(t, body["created_at"])
	assert.NotEmpty(t, body["updated_at"])

	assert.Equal(t, "rate_limiter", body["slug"])
	assert.Equal(t, true, body["enabled"])
}

func TestCreatePolicy_WithDescription(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw-desc")})

	name := uniqueName("pol-desc")
	payload := validPolicyPayload(name)
	payload["description"] = "limits requests per minute"

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)

	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, "limits requests per minute", body["description"])
}

func TestCreatePolicy_ValidationMissingSlug(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw2")})

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, map[string]any{
		"name": uniqueName("pol-noslug"),
	})
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreatePolicy_Conflict(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw3")})
	name := uniqueName("pol-dup")
	_ = CreatePolicy(t, gwID, validPolicyPayload(name))

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(name))
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreatePolicy_AllowsSameNameAcrossGateways(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gw1 := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gwA")})
	gw2 := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gwB")})

	name := uniqueName("pol-cross")
	_ = CreatePolicy(t, gw1, validPolicyPayload(name))

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gw2)
	status, _ := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(name))
	require.Equal(t, http.StatusCreated, status)
}

func TestCreatePolicy_ValidationEmptyName(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw4")})

	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, map[string]any{"name": ""})
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreatePolicy_ValidationUnknownStage(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("pol-gw5")})

	payload := map[string]any{
		"name":   uniqueName("pol-stage"),
		"slug":   "rate_limiter",
		"stages": []string{"bogus_stage"},
	}
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, payload)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreatePolicy_GatewayNotFound(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	missing := uuid.NewString()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies", AdminURL, missing)
	status, body := sendRequest(t, http.MethodPost, url, nil, validPolicyPayload(uniqueName("pol-orphan")))
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreatePolicy_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "CreatePolicy")()
	status, body := sendRequest(t, http.MethodPost,
		AdminURL+"/v1/gateways/not-a-uuid/policies", nil,
		validPolicyPayload(uniqueName("pol-bad")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
