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

	beIDs, ok := body["registry_ids"].([]any)
	require.True(t, ok, "registry_ids missing: %v", body)
	assert.Empty(t, beIDs)
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
