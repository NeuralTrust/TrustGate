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
	name := uniqueName("co-create-ok")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil,
		validConsumerPayload(name),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	assert.NotEmpty(t, body["id"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "LLM", body["type"])
	assert.Equal(t, true, body["active"])

	// A consumer created without registries carries no associations.
	bindings, ok := body["registries"].([]any)
	require.True(t, ok, "registries missing: %v", body)
	assert.Empty(t, bindings)
}

// TestCreateConsumer_WithRegistriesAndModelPolicies covers the atomic create
// path: associations and per-registry model policies are accepted in a single
// POST through the nested registries array.
func TestCreateConsumer_WithRegistriesAndModelPolicies(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-create-bind-gw")})
	be1 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-create-bind-be1")))
	be2 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-create-bind-be2")))
	name := uniqueName("co-create-bind")

	payload := validConsumerPayload(name)
	payload["registries"] = []map[string]any{
		{"id": be1, "model_policies": map[string]any{"allowed": []string{"gpt-4o", "gpt-4o-mini"}, "default": "gpt-4o"}},
		{"id": be2},
	}
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	got := registryIDSet(t, body)
	require.Len(t, got, 2)
	assert.Contains(t, got, be1)
	assert.Contains(t, got, be2)

	bindings := body["registries"].([]any)
	for _, raw := range bindings {
		binding := raw.(map[string]any)
		policy, hasPolicy := binding["model_policies"].(map[string]any)
		switch binding["id"] {
		case be1:
			require.True(t, hasPolicy, "policy missing for %s: %v", be1, binding)
			assert.Equal(t, "gpt-4o", policy["default"])
		case be2:
			assert.False(t, hasPolicy, "unexpected policy for %s: %v", be2, binding)
		}
	}
}

// TestCreateConsumer_RejectsRegistryFromAnotherGateway ensures ownership is
// validated before persisting anything: a registry created under a different
// gateway cannot be bound at create time.
func TestCreateConsumer_RejectsRegistryFromAnotherGateway(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-create-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-create-xgw-b")})
	foreignBE := CreateRegistry(t, gwB, validRegistryPayload(uniqueName("co-create-xgw-be")))

	payload := validConsumerPayload(uniqueName("co-create-xgw"))
	payload["registries"] = []map[string]any{{"id": foreignBE}}
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwA),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_ConflictSameGateway(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-conflict-gw")})
	name := uniqueName("co-conflict")

	_ = CreateConsumer(t, gwID, validConsumerPayload(name))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil,
		validConsumerPayload(name),
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreateConsumer_SameNameDifferentGatewaysAllowed(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-shared-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-shared-b")})
	shared := uniqueName("co-shared-name")

	_ = CreateConsumer(t, gwA, validConsumerPayload(shared))
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwB),
		nil,
		validConsumerPayload(shared),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
}

func TestCreateConsumer_GatewayDoesNotExist(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	missingGW := uuid.NewString()
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, missingGW),
		nil,
		validConsumerPayload(uniqueName("co-no-gw")),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	status, body := sendRequest(t, http.MethodPost,
		AdminURL+"/v1/gateways/not-a-uuid/consumers",
		nil,
		validConsumerPayload(uniqueName("co-invalid-uuid")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestCreateConsumer_ValidationEmptyName(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-emptyname-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload(""),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_ValidationEmptyPath(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-emptypath-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, map[string]any{
			"name": uniqueName("co-empty-path"),
			"path": "",
		},
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
	name := uniqueName("co-deftype")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload(name),
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
			payload := validConsumerPayload(uniqueName("co-" + ty))
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

	payload := validConsumerPayload(uniqueName("co-badtype"))
	payload["type"] = "foo"

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
