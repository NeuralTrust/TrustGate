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

func TestCreateConsumer_Success(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-create-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-create-be")))
	name := uniqueName("co-create-ok")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil,
		validConsumerPayload(name, beID),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	assert.NotEmpty(t, body["id"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "LLM", body["type"])
	assert.Equal(t, true, body["active"])

	beIDs, ok := body["registry_ids"].([]any)
	require.True(t, ok, "registry_ids missing: %v", body)
	require.Len(t, beIDs, 1)
	assert.Equal(t, beID, beIDs[0])
}

func TestCreateConsumer_ConflictSameGateway(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-conflict-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-conflict-be")))
	name := uniqueName("co-conflict")

	_ = CreateConsumer(t, gwID, validConsumerPayload(name, beID))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil,
		validConsumerPayload(name, beID),
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreateConsumer_SameNameDifferentGatewaysAllowed(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-shared-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-shared-b")})
	beA := CreateRegistry(t, gwA, validRegistryPayload(uniqueName("co-shared-be-a")))
	beB := CreateRegistry(t, gwB, validRegistryPayload(uniqueName("co-shared-be-b")))
	shared := uniqueName("co-shared-name")

	_ = CreateConsumer(t, gwA, validConsumerPayload(shared, beA))
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwB),
		nil,
		validConsumerPayload(shared, beB),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
}

func TestCreateConsumer_GatewayDoesNotExist(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	missingGW := uuid.NewString()
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, missingGW),
		nil,
		validConsumerPayload(uniqueName("co-no-gw"), uuid.NewString()),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	status, body := sendRequest(t, http.MethodPost,
		AdminURL+"/v1/gateways/not-a-uuid/consumers",
		nil,
		validConsumerPayload(uniqueName("co-invalid-uuid"), uuid.NewString()),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestCreateConsumer_ValidationEmptyName(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-emptyname-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-emptyname-be")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload("", beID),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_ValidationEmptyRegistryIDs(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-emptybes-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, map[string]any{
			"name":         uniqueName("co-empty-bes"),
			"registry_ids": []string{},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_ValidationBadBackendUUID(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-badbe-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, map[string]any{
			"name":         uniqueName("co-bad-be"),
			"registry_ids": []string{"not-a-uuid"},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_UnknownBackend(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-ghost-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload(uniqueName("co-ghost"), uuid.NewString()),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_BackendFromDifferentGateway(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-xgw-b")})
	beA := CreateRegistry(t, gwA, validRegistryPayload(uniqueName("co-xgw-be")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwB),
		nil, validConsumerPayload(uniqueName("co-xgw"), beA),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_InvalidBody(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-badbody-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, "not-an-object",
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_TypeDefaultsToLLM(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-deftype-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-deftype-be")))
	name := uniqueName("co-deftype")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload(name, beID),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, "LLM", body["type"])
}

func TestCreateConsumer_TypeMCPAndA2A(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	for _, ty := range []string{"MCP", "A2A"} {
		ty := ty
		t.Run(ty, func(t *testing.T) {
			gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-" + ty + "-gw")})
			beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-"+ty+"-be")))
			payload := validConsumerPayload(uniqueName("co-"+ty), beID)
			payload["type"] = ty

			status, body := sendRequest(t, http.MethodPost,
				fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
				nil, payload,
			)
			require.Equal(t, http.StatusCreated, status, "body=%v", body)
			assert.Equal(t, ty, body["type"])
		})
	}
}

func TestCreateConsumer_InvalidType(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-badtype-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-badtype-be")))

	payload := validConsumerPayload(uniqueName("co-badtype"), beID)
	payload["type"] = "foo"

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

// TestCreateConsumer_WithModelPolicies stores an allow-list and default model
// bound to a backend and asserts the API echoes them back on the response.
func TestCreateConsumer_WithModelPolicies(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-mp-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-mp-be")))

	payload := validConsumerPayload(uniqueName("co-mp"), beID)
	payload["model_policies"] = []map[string]any{
		{"registry_id": beID, "allowed": []string{"gpt-4o-mini", "gpt-4o"}, "default": "gpt-4o-mini"},
	}

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	policies, ok := body["model_policies"].([]any)
	require.True(t, ok, "model_policies missing: %v", body)
	require.Len(t, policies, 1)

	policy, ok := policies[0].(map[string]any)
	require.True(t, ok, "model policy entry malformed: %v", policies[0])
	assert.Equal(t, beID, policy["registry_id"])
	assert.Equal(t, "gpt-4o-mini", policy["default"])

	allowed, ok := policy["allowed"].([]any)
	require.True(t, ok, "allowed missing: %v", policy)
	assert.ElementsMatch(t, []any{"gpt-4o-mini", "gpt-4o"}, allowed)
}

// TestCreateConsumer_ModelPolicyUnknownBackend rejects a policy bound to a
// backend that is neither in the pool nor the fallback chain.
func TestCreateConsumer_ModelPolicyUnknownBackend(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-mp-ghost-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-mp-ghost-be")))

	payload := validConsumerPayload(uniqueName("co-mp-ghost"), beID)
	payload["model_policies"] = []map[string]any{
		{"registry_id": uuid.NewString(), "allowed": []string{"gpt-4o-mini"}},
	}

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

// TestCreateConsumer_ModelPolicyDefaultNotAllowed rejects a default model that
// is absent from its own allow-list.
func TestCreateConsumer_ModelPolicyDefaultNotAllowed(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-mp-def-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-mp-def-be")))

	payload := validConsumerPayload(uniqueName("co-mp-def"), beID)
	payload["model_policies"] = []map[string]any{
		{"registry_id": beID, "allowed": []string{"gpt-4o-mini"}, "default": "gpt-4o"},
	}

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
