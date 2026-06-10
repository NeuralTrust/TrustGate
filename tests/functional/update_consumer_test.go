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
	original := uniqueName("co-upd-from")
	coID := CreateConsumer(t, gwID, validConsumerPayload(original))

	updatedName := uniqueName("co-upd-to")
	payload := validConsumerPayload(updatedName)
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

// TestUpdateConsumer_PreservesAssociations verifies that an update touching only
// base config does not disturb the registry associations managed through the
// link endpoints.
func TestUpdateConsumer_PreservesAssociations(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-keep-gw")})
	be1 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-keep-be1")))
	be2 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-keep-be2")))
	name := uniqueName("co-upd-keep")
	coID := CreateConsumerWithRegistries(t, gwID, name, be1, be2)

	payload := validConsumerPayload(name)
	payload["headers"] = map[string]string{"X-Env": "prod"}
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, payload,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	got := registryIDSet(t, getConsumer(t, gwID, coID))
	require.Len(t, got, 2, "update must not drop associations")
	assert.Contains(t, got, be1)
	assert.Contains(t, got, be2)
}

// TestUpdateConsumer_SetsModelPolicies attaches a registry, then binds a model
// policy through an update and asserts it is persisted and returned.
func TestUpdateConsumer_SetsModelPolicies(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-mp-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-mp-be")))
	name := uniqueName("co-upd-mp")
	coID := CreateConsumerWithRegistries(t, gwID, name, beID)

	payload := validConsumerPayload(name)
	payload["registries"] = []map[string]any{
		{"id": beID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o-mini"}},
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

	registries, ok := body["registries"].([]any)
	require.True(t, ok, "registries missing after update: %v", body)
	require.Len(t, registries, 1)
	binding, ok := registries[0].(map[string]any)
	require.True(t, ok, "registry binding malformed: %v", registries[0])
	assert.Equal(t, beID, binding["id"])
	policy, ok := binding["model_policies"].(map[string]any)
	require.True(t, ok, "model_policies missing on binding: %v", binding)
	assert.Equal(t, "gpt-4o-mini", policy["default"])
}

// TestUpdateConsumer_RejectsModelPolicyForUnassociatedRegistry ensures a model
// policy can only reference a registry already attached to the consumer.
func TestUpdateConsumer_RejectsModelPolicyForUnassociatedRegistry(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-mp-unassoc-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-mp-unassoc-be")))
	name := uniqueName("co-upd-mp-unassoc")
	coID := CreateConsumer(t, gwID, validConsumerPayload(name)) // registry NOT attached

	payload := validConsumerPayload(name)
	payload["registries"] = []map[string]any{
		{"id": beID, "model_policies": map[string]any{"allowed": []string{"gpt-4o-mini"}}},
	}
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateConsumer_Partial(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-partial-gw")})
	name := uniqueName("co-upd-partial")
	coID := CreateConsumer(t, gwID, validConsumerPayload(name))
	expectedPath := "/v1/" + name

	renamed := uniqueName("co-upd-partial-to")
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"name": renamed})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, renamed, body["name"])

	status, body = sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, renamed, body["name"])
	assert.Equal(t, expectedPath, body["path"], "path must be preserved on a partial update")
}

func TestUpdateConsumer_Partial_EmptyTypePreservesExisting(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-empty-type-gw")})
	name := uniqueName("co-upd-empty-type")
	payload := validConsumerPayload(name)
	payload["type"] = "MCP"
	coID := CreateConsumer(t, gwID, payload)

	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"type": ""})
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	status, body = sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "MCP", body["type"], "empty type must be treated as no-change, not reset to LLM")
}

func TestUpdateConsumer_NotFound(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-missing-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, missing),
		nil,
		validConsumerPayload(uniqueName("co-upd-missing")),
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestUpdateConsumer_ValidationEmptyName(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-val-gw")})
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("co-upd-val")))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, validConsumerPayload(""),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateConsumer_NameConflictSameGateway(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-upd-conflict-gw")})
	a := uniqueName("co-upd-a")
	b := uniqueName("co-upd-b")
	_ = CreateConsumer(t, gwID, validConsumerPayload(a))
	bID := CreateConsumer(t, gwID, validConsumerPayload(b))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, bID),
		nil, validConsumerPayload(a),
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestUpdateConsumer_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/consumers/%s", AdminURL, uuid.NewString()),
		nil,
		validConsumerPayload(uniqueName("co-upd-bad-gw")),
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
		validConsumerPayload(uniqueName("co-upd-bad-co")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
