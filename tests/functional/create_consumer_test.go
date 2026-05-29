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
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-create-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("co-create-be")))
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
	assert.Equal(t, "/v1/chat", body["path"])
	assert.Equal(t, true, body["active"])
	assert.Equal(t, false, body["public"])
	assert.Equal(t, float64(1), body["retry_attempts"])

	beIDs, ok := body["backend_ids"].([]any)
	require.True(t, ok, "backend_ids missing: %v", body)
	require.Len(t, beIDs, 1)
	assert.Equal(t, beID, beIDs[0])

	methods, ok := body["methods"].([]any)
	require.True(t, ok)
	require.Len(t, methods, 1)
	assert.Equal(t, "POST", methods[0])
}

func TestCreateConsumer_ConflictSameGateway(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-conflict-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("co-conflict-be")))
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
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-shared-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-shared-b")})
	beA := CreateBackend(t, gwA, validBackendPayload(uniqueName("co-shared-be-a")))
	beB := CreateBackend(t, gwB, validBackendPayload(uniqueName("co-shared-be-b")))
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
	status, body := sendRequest(t, http.MethodPost,
		AdminURL+"/v1/gateways/not-a-uuid/consumers",
		nil,
		validConsumerPayload(uniqueName("co-invalid-uuid"), uuid.NewString()),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestCreateConsumer_ValidationEmptyName(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-emptyname-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("co-emptyname-be")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload("", beID),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_ValidationEmptyBackendIDs(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-emptybes-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, map[string]any{
			"name":        uniqueName("co-empty-bes"),
			"path":        "/v1/chat",
			"backend_ids": []string{},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_ValidationBadBackendUUID(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-badbe-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, map[string]any{
			"name":        uniqueName("co-bad-be"),
			"path":        "/v1/chat",
			"backend_ids": []string{"not-a-uuid"},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_UnknownBackend(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-ghost-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload(uniqueName("co-ghost"), uuid.NewString()),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_BackendFromDifferentGateway(t *testing.T) {
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-xgw-b")})
	beA := CreateBackend(t, gwA, validBackendPayload(uniqueName("co-xgw-be")))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwB),
		nil, validConsumerPayload(uniqueName("co-xgw"), beA),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_InvalidBody(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-badbody-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, "not-an-object",
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_TypeDefaultsToLLM(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-deftype-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("co-deftype-be")))
	name := uniqueName("co-deftype")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload(name, beID),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, "LLM", body["type"])
}

func TestCreateConsumer_TypeMCPAndA2A(t *testing.T) {
	for _, ty := range []string{"MCP", "A2A"} {
		ty := ty
		t.Run(ty, func(t *testing.T) {
			gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-" + ty + "-gw")})
			beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("co-"+ty+"-be")))
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
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-badtype-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("co-badtype-be")))

	payload := validConsumerPayload(uniqueName("co-badtype"), beID)
	payload["type"] = "foo"

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
