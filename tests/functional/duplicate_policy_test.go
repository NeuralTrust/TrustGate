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

func duplicatePolicy(t *testing.T, gatewayID, policyID string) (int, map[string]any) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s/duplicate", AdminURL, gatewayID, policyID)
	return sendRequest(t, http.MethodPost, url, nil, nil)
}

func TestDuplicatePolicy_Success(t *testing.T) {
	defer Track(t, "DuplicatePolicy")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("dup-gw")})
	name := uniqueName("dup-src")
	srcID := CreatePolicy(t, gwID, validPolicyPayload(name))

	getURL := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, srcID)
	_, srcBody := sendRequest(t, http.MethodGet, getURL, nil, nil)

	status, body := duplicatePolicy(t, gwID, srcID)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	assert.Equal(t, name+" 2", body["name"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.Equal(t, "rate_limiter", body["slug"])
	assert.Equal(t, true, body["enabled"])
	assert.Equal(t, srcBody["settings"], body["settings"])
	assert.NotEmpty(t, body["id"])
	assert.NotEqual(t, srcID, body["id"])
}

func TestDuplicatePolicy_DoesNotCopyGlobalOrConsumers(t *testing.T) {
	defer Track(t, "DuplicatePolicy")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("dup-gw2")})
	name := uniqueName("dup-scoped")
	srcID := CreatePolicy(t, gwID, validPolicyPayload(name))

	consumerID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("dup-con")))
	AttachPolicy(t, gwID, consumerID, srcID)
	SetPolicyGlobal(t, gwID, srcID)

	status, body := duplicatePolicy(t, gwID, srcID)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	assert.Equal(t, false, body["global"], "duplicate must not inherit global scope")
	assert.Nil(t, body["consumer_ids"], "duplicate must start with no consumers")
}

func TestDuplicatePolicy_TwiceIncrementsSuffix(t *testing.T) {
	defer Track(t, "DuplicatePolicy")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("dup-gw3")})
	name := uniqueName("dup-seq")
	srcID := CreatePolicy(t, gwID, validPolicyPayload(name))

	status1, body1 := duplicatePolicy(t, gwID, srcID)
	require.Equal(t, http.StatusCreated, status1, "body=%v", body1)
	assert.Equal(t, name+" 2", body1["name"])

	status2, body2 := duplicatePolicy(t, gwID, srcID)
	require.Equal(t, http.StatusCreated, status2, "body=%v", body2)
	assert.Equal(t, name+" 3", body2["name"])
}

func TestDuplicatePolicy_NotFound(t *testing.T) {
	defer Track(t, "DuplicatePolicy")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("dup-gw4")})
	status, body := duplicatePolicy(t, gwID, uuid.NewString())
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDuplicatePolicy_InvalidUUID(t *testing.T) {
	defer Track(t, "DuplicatePolicy")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("dup-gw5")})
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/not-a-uuid/duplicate", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodPost, url, nil, nil)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
