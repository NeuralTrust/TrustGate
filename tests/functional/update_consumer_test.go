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

func TestUpdateConsumer_Success(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-be")))
	original := uniqueName("co-upd-from")
	coID := CreateConsumer(t, gwID, validConsumerPayload(original, beID))

	updatedName := uniqueName("co-upd-to")
	payload := validConsumerPayload(updatedName, beID)
	payload["headers"] = map[string]string{"X-Tenant": "acme"}

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, payload,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, updatedName, body["name"])

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, updatedName, body["name"])
}

func TestUpdateConsumer_RebindsBackends(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-rebind-gw")})
	be1 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-rebind-be1")))
	be2 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-rebind-be2")))
	be3 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-rebind-be3")))
	name := uniqueName("co-upd-rebind")
	coID := CreateConsumer(t, gwID, map[string]any{
		"name":         name,
		"path":         "/v1/" + name,
		"registry_ids": []string{be1, be2},
	})

	payload := map[string]any{
		"name":         name,
		"path":         "/v1/" + name,
		"registry_ids": []string{be2, be3},
	}
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, payload,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status)
	beIDs, ok := body["registry_ids"].([]any)
	require.True(t, ok, "registry_ids missing: %v", body)
	require.Len(t, beIDs, 2)
	got := map[string]bool{}
	for _, raw := range beIDs {
		id, _ := raw.(string)
		got[id] = true
	}
	assert.True(t, got[be2], "expected be2 still attached")
	assert.True(t, got[be3], "expected be3 attached after update")
	assert.False(t, got[be1], "be1 must have been detached")
}

// TestUpdateConsumer_SetsModelPolicies attaches a model policy through an update
// and asserts it is persisted and returned on a subsequent read.
func TestUpdateConsumer_SetsModelPolicies(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-mp-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-mp-be")))
	name := uniqueName("co-upd-mp")
	coID := CreateConsumer(t, gwID, validConsumerPayload(name, beID))

	payload := validConsumerPayload(name, beID)
	payload["model_policies"] = []map[string]any{
		{"registry_id": beID, "allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o-mini"},
	}
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, payload,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status)

	policies, ok := body["model_policies"].([]any)
	require.True(t, ok, "model_policies missing after update: %v", body)
	require.Len(t, policies, 1)
	policy, ok := policies[0].(map[string]any)
	require.True(t, ok, "model policy entry malformed: %v", policies[0])
	assert.Equal(t, beID, policy["registry_id"])
	assert.Equal(t, "gpt-4o-mini", policy["default"])
}

func TestUpdateConsumer_NotFound(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-missing-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-missing-be")))
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, missing),
		nil,
		validConsumerPayload(uniqueName("co-upd-missing"), beID),
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestUpdateConsumer_ValidationEmptyName(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-val-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-val-be")))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("co-upd-val"), beID))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, validConsumerPayload("", beID),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateConsumer_NameConflictSameGateway(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-conflict-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-conflict-be")))
	a := uniqueName("co-upd-a")
	b := uniqueName("co-upd-b")
	_ = CreateConsumer(t, gwID, validConsumerPayload(a, beID))
	bID := CreateConsumer(t, gwID, validConsumerPayload(b, beID))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, bID),
		nil, validConsumerPayload(a, beID),
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestUpdateConsumer_RejectsCrossGatewayRegistry(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-xgw-b")})
	beA := CreateRegistry(t, gwA, validRegistryPayload(uniqueName("co-upd-xgw-be-a")))
	beB := CreateRegistry(t, gwB, validRegistryPayload(uniqueName("co-upd-xgw-be-b")))
	coID := CreateConsumer(t, gwA, validConsumerPayload(uniqueName("co-upd-xgw"), beA))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwA, coID),
		nil, validConsumerPayload(uniqueName("co-upd-xgw"), beB),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateConsumer_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/consumers/%s", AdminURL, uuid.NewString()),
		nil,
		validConsumerPayload(uniqueName("co-upd-bad-gw"), uuid.NewString()),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestUpdateConsumer_InvalidConsumerUUID(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-bad-co-gw")})

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/not-a-uuid", AdminURL, gwID),
		nil,
		validConsumerPayload(uniqueName("co-upd-bad-co"), uuid.NewString()),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
