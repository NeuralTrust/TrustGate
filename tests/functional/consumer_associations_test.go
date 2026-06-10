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

// getConsumer fetches a consumer and returns the decoded body, failing on a
// non-200 status.
func getConsumer(t *testing.T, gatewayID, consumerID string) map[string]any {
	t.Helper()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gatewayID, consumerID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "get consumer failed: %v", body)
	return body
}

// getPolicy fetches a policy and returns the decoded body, failing on a
// non-200 status.
func getPolicy(t *testing.T, gatewayID, policyID string) map[string]any {
	t.Helper()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gatewayID, policyID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "get policy failed: %v", body)
	return body
}

func idSet(t *testing.T, body map[string]any, key string) map[string]struct{} {
	t.Helper()
	raw, _ := body[key].([]any)
	out := make(map[string]struct{}, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		out[s] = struct{}{}
	}
	return out
}

// registryIDSet extracts the bound registry ids from the nested registries
// array of a consumer response.
func registryIDSet(t *testing.T, body map[string]any) map[string]struct{} {
	t.Helper()
	raw, _ := body["registries"].([]any)
	out := make(map[string]struct{}, len(raw))
	for _, v := range raw {
		entry, _ := v.(map[string]any)
		s, _ := entry["id"].(string)
		out[s] = struct{}{}
	}
	return out
}

func TestAttachRegistry_RoundTrip(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("assoc-be-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("assoc-be")))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-be-co")))

	AttachRegistry(t, gwID, coID, beID)
	// Re-attach must be idempotent (204, no duplicate).
	AttachRegistry(t, gwID, coID, beID)

	got := registryIDSet(t, getConsumer(t, gwID, coID))
	require.Len(t, got, 1)
	assert.Contains(t, got, beID)

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/registries/%s", AdminURL, gwID, coID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	got = registryIDSet(t, getConsumer(t, gwID, coID))
	assert.Empty(t, got, "registry should be detached")
}

func TestAttachRegistry_UnknownRegistry(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("assoc-be-ghost-gw")})
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-be-ghost-co")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/registries/%s", AdminURL, gwID, coID, uuid.NewString()),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestAttachRegistry_CrossGatewayRejected(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("assoc-be-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("assoc-be-xgw-b")})
	beB := CreateRegistry(t, gwB, validRegistryPayload(uniqueName("assoc-be-xgw-be")))
	coA := CreateConsumer(t, gwA, validConsumerPayload(uniqueName("assoc-be-xgw-co")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/registries/%s", AdminURL, gwA, coA, beB),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestAttachRegistry_UnknownConsumer(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("assoc-be-noco-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("assoc-be-noco-be")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/registries/%s", AdminURL, gwID, uuid.NewString(), beID),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestAttachRegistry_InvalidUUID(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("assoc-be-baduuid-gw")})
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-be-baduuid-co")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/registries/not-a-uuid", AdminURL, gwID, coID),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestAttachAuth_RoundTrip(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("assoc-auth-gw")})
	authID := CreateAuth(t, gwID, validAuthPayload(uniqueName("assoc-auth")))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-auth-co")))

	AttachAuth(t, gwID, coID, authID)

	got := idSet(t, getConsumer(t, gwID, coID), "auth_ids")
	require.Len(t, got, 1)
	assert.Contains(t, got, authID)

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/auths/%s", AdminURL, gwID, coID, authID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	got = idSet(t, getConsumer(t, gwID, coID), "auth_ids")
	assert.Empty(t, got, "auth should be detached")
}

func TestAttachAuth_CrossGatewayRejected(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("assoc-auth-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("assoc-auth-xgw-b")})
	authB := CreateAuth(t, gwB, validAuthPayload(uniqueName("assoc-auth-xgw-auth")))
	coA := CreateConsumer(t, gwA, validConsumerPayload(uniqueName("assoc-auth-xgw-co")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/auths/%s", AdminURL, gwA, coA, authB),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestAttachPolicy_RoundTrip(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("assoc-pol-gw")})
	policyID := CreatePolicy(t, gwID, validPolicyPayload(uniqueName("assoc-pol")))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-pol-co")))

	AttachPolicy(t, gwID, coID, policyID)

	// The link surfaces on the policy's consumer projection.
	got := idSet(t, getPolicy(t, gwID, policyID), "consumer_ids")
	require.Len(t, got, 1)
	assert.Contains(t, got, coID)

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/policies/%s", AdminURL, gwID, coID, policyID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	got = idSet(t, getPolicy(t, gwID, policyID), "consumer_ids")
	assert.Empty(t, got, "policy link should be removed")
}

func TestAttachPolicy_CrossGatewayRejected(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("assoc-pol-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("assoc-pol-xgw-b")})
	policyB := CreatePolicy(t, gwB, validPolicyPayload(uniqueName("assoc-pol-xgw-pol")))
	coA := CreateConsumer(t, gwA, validConsumerPayload(uniqueName("assoc-pol-xgw-co")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/policies/%s", AdminURL, gwA, coA, policyB),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestPolicyGlobalScope_SetAndUnset(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("assoc-global-gw")})
	policyID := CreatePolicy(t, gwID, validPolicyPayload(uniqueName("assoc-global-pol")))

	// A freshly created policy is consumer-scoped (not global).
	assert.Equal(t, false, getPolicy(t, gwID, policyID)["global"])

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/policies/%s/global", AdminURL, gwID, policyID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, true, body["global"])
	assert.Equal(t, true, getPolicy(t, gwID, policyID)["global"])

	status, body = sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/policies/%s/global", AdminURL, gwID, policyID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, false, body["global"])
	assert.Equal(t, false, getPolicy(t, gwID, policyID)["global"])
}

func TestPolicyGlobalScope_CrossGatewayRejected(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("assoc-global-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("assoc-global-xgw-b")})
	policyA := CreatePolicy(t, gwA, validPolicyPayload(uniqueName("assoc-global-xgw-pol")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/policies/%s/global", AdminURL, gwB, policyA),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}
