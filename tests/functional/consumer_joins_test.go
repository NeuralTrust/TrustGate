package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateConsumer_WithPolicyAndAuthJoins(t *testing.T) {
	defer Track(t, "ConsumerJoins")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-joins-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-joins-be")))
	policyID := CreatePolicy(t, gwID, validPolicyPayload(uniqueName("co-joins-pol")))
	authID := CreateAuth(t, gwID, validAuthPayload(uniqueName("co-joins-auth")))

	payload := validConsumerPayload(uniqueName("co-joins"), beID)
	payload["policy_ids"] = []string{policyID}
	payload["auth_ids"] = []string{authID}

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	policyIDs, ok := body["policy_ids"].([]any)
	require.True(t, ok, "policy_ids missing: %v", body)
	require.Len(t, policyIDs, 1)
	assert.Equal(t, policyID, policyIDs[0])

	authIDs, ok := body["auth_ids"].([]any)
	require.True(t, ok, "auth_ids missing: %v", body)
	require.Len(t, authIDs, 1)
	assert.Equal(t, authID, authIDs[0])
}

func TestCreateConsumer_PolicyFromDifferentGatewayRejected(t *testing.T) {
	defer Track(t, "ConsumerJoins")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-xpol-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-xpol-b")})
	beB := CreateRegistry(t, gwB, validRegistryPayload(uniqueName("co-xpol-be")))
	policyA := CreatePolicy(t, gwA, validPolicyPayload(uniqueName("co-xpol-pol")))

	payload := validConsumerPayload(uniqueName("co-xpol"), beB)
	payload["policy_ids"] = []string{policyA}

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwB),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_UnknownAuthRejected(t *testing.T) {
	defer Track(t, "ConsumerJoins")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-ghostauth-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-ghostauth-be")))

	payload := validConsumerPayload(uniqueName("co-ghostauth"), beID)
	payload["auth_ids"] = []string{uuid.NewString()}

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateConsumer_ReplacesJoins(t *testing.T) {
	defer Track(t, "ConsumerJoins")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upjoin-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upjoin-be")))
	authID := CreateAuth(t, gwID, validAuthPayload(uniqueName("co-upjoin-auth")))

	id := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("co-upjoin"), beID))

	payload := validConsumerPayload(uniqueName("co-upjoin-renamed"), beID)
	payload["auth_ids"] = []string{authID}

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, id),
		nil, payload,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	authIDs, ok := body["auth_ids"].([]any)
	require.True(t, ok, "auth_ids missing: %v", body)
	require.Len(t, authIDs, 1)
	assert.Equal(t, authID, authIDs[0])
}
