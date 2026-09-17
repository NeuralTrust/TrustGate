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

func TestAttachRegistry_RoundTrip(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-be-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("assoc-be")))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-be-co")))

	AttachRegistry(t, gwID, coID, beID)
	// Re-attach must be idempotent (204, no duplicate).
	AttachRegistry(t, gwID, coID, beID)

	got := idSet(t, getConsumer(t, gwID, coID), "registry_ids")
	require.Len(t, got, 1)
	assert.Contains(t, got, beID)

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/registries/%s", AdminURL, gwID, coID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	got = idSet(t, getConsumer(t, gwID, coID), "registry_ids")
	assert.Empty(t, got, "registry should be detached")
}

func TestAttachRegistry_UnknownRegistry(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-be-ghost-gw")})
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
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-be-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-be-xgw-b")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-be-noco-gw")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-be-baduuid-gw")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-auth-gw")})
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
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-auth-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-auth-xgw-b")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-pol-gw")})
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
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-pol-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-pol-xgw-b")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-global-gw")})
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
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-global-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-global-xgw-b")})
	policyA := CreatePolicy(t, gwA, validPolicyPayload(uniqueName("assoc-global-xgw-pol")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/policies/%s/global", AdminURL, gwB, policyA),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

// A scope naming a registry stays refused on an LLM consumer: the destination
// dimension has no meaning outside MCP, so the policy would be attached and
// never run.
func TestAttachPolicy_ScopedPolicyOnLLMConsumerRejected(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-scope-llm-gw")})
	registryID := createMCPRegistry(t, gwID)
	policyID := CreatePolicy(t, gwID, scopedPolicyPayload(uniqueName("assoc-scope-pol"), map[string]any{
		"registry_ids": []string{registryID},
	}))
	llmConsumer := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-scope-llm-co")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/policies/%s", AdminURL, gwID, llmConsumer, policyID),
		nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
	assert.Empty(t, idSet(t, getPolicy(t, gwID, policyID), "consumer_ids"), "rejected attach leaves no link")
}

// The second reason for the 422 is the plugin, not the dimension: a group-only
// scope would cross, but rate_limiter never opted into running where the scope
// does not gate, so it is refused as well. Every production plugin looks like
// this today (RUN-1621, open question 2).
func TestAttachPolicy_GroupScopedPolicyOnLLMConsumerRejectedForTheNonInertPlugin(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-grp-llm-gw")})
	policyID := CreatePolicy(t, gwID, scopedPolicyPayload(uniqueName("assoc-grp-pol"), map[string]any{
		"groups": []string{"finance"},
	}))
	llmConsumer := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-grp-llm-co")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/policies/%s", AdminURL, gwID, llmConsumer, policyID),
		nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
	assert.Empty(t, idSet(t, getPolicy(t, gwID, policyID), "consumer_ids"), "rejected attach leaves no link")
}

// The combination the guard allows: a scope that narrows by group alone over a
// plugin that does not resolve tool or registry names. It is a 204, and the
// policy then runs on the consumer's LLM traffic with the group inert.
func TestAttachPolicy_GroupScopedPolicyOnLLMConsumerAccepted(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	t.Skip("no production plugin returns ScopeInertSafe() == true yet: which ones may is the open product decision RUN-1621 Q2. Unskip once one does, using its slug here.")
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-inert-llm-gw")})
	payload := scopedPolicyPayload(uniqueName("assoc-inert-pol"), map[string]any{
		"groups": []string{"finance"},
	})
	policyID := CreatePolicy(t, gwID, payload)
	llmConsumer := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("assoc-inert-llm-co")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/policies/%s", AdminURL, gwID, llmConsumer, policyID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status, "body=%v", body)
	assert.Equal(t, map[string]struct{}{llmConsumer: {}}, idSet(t, getPolicy(t, gwID, policyID), "consumer_ids"))
}

// Attaching a scoped policy answers 204 unless the consumer already runs the
// same plugin without scope, in which case the link is still made and the
// overlap is reported as a 200 with warnings.
func TestAttachPolicy_ScopedPolicyWarnsOnUnscopedOverlap(t *testing.T) {
	defer Track(t, "ConsumerAssociations")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("assoc-scope-warn-gw")})
	registryID := createMCPRegistry(t, gwID)
	withUnscoped, _ := createMCPConsumer(t, gwID, []string{registryID}, nil, "")
	clean, _ := createMCPConsumer(t, gwID, []string{registryID}, nil, "")
	unscopedID := CreatePolicy(t, gwID, validPolicyPayload(uniqueName("assoc-scope-unscoped")))
	AttachPolicy(t, gwID, withUnscoped, unscopedID)
	scopedID := CreatePolicy(t, gwID, scopedPolicyPayload(uniqueName("assoc-scope-scoped"), map[string]any{
		"registry_ids": []string{registryID},
	}))

	AttachPolicy(t, gwID, clean, scopedID)

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/policies/%s", AdminURL, gwID, withUnscoped, scopedID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	warnings, _ := body["warnings"].([]any)
	require.Len(t, warnings, 1, "body=%v", body)
	assert.Contains(t, warnings[0], withUnscoped)
	assert.Contains(t, warnings[0], "rate_limiter")

	got := idSet(t, getPolicy(t, gwID, scopedID), "consumer_ids")
	assert.Contains(t, got, withUnscoped, "the warned attach is still made")
	assert.Contains(t, got, clean)
}
