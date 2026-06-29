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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-create-gw")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-conflict-gw")})
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
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("co-shared-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("co-shared-b")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-emptyname-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, validConsumerPayload(""),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_GeneratesSlug(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-slug-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, map[string]any{"name": uniqueName("co-slug")},
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	slug, ok := body["slug"].(string)
	require.True(t, ok, "response must expose the generated slug: %v", body)
	assert.Len(t, slug, 8, "slug must be 8 chars")
	for _, c := range slug {
		assert.True(t, (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			"slug must be alphanumeric, got %q", slug)
	}
}

func TestCreateConsumer_RoleBasedWithRoles(t *testing.T) {
	defer Track(t, "CreateConsumer")()

	t.Run("existing role is bound atomically", func(t *testing.T) {
		gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-roles-gw")})
		roleID := CreateRole(t, gwID, map[string]any{"name": uniqueName("co-role")})

		status, body := sendRequest(t, http.MethodPost,
			fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
			nil, map[string]any{
				"name":         uniqueName("co-roles"),
				"routing_mode": "role_based",
				"roles":        []string{roleID},
			},
		)
		require.Equal(t, http.StatusCreated, status, "body=%v", body)

		roleIDs, ok := body["role_ids"].([]any)
		require.True(t, ok, "role_ids missing: %v", body)
		require.Len(t, roleIDs, 1)
		assert.Equal(t, roleID, roleIDs[0])
	})

	t.Run("role from another gateway is rejected", func(t *testing.T) {
		gwA := CreateGateway(t, map[string]any{"slug": uniqueName("co-roles-gw-a")})
		gwB := CreateGateway(t, map[string]any{"slug": uniqueName("co-roles-gw-b")})
		foreignRole := CreateRole(t, gwA, map[string]any{"name": uniqueName("co-role-foreign")})

		status, body := sendRequest(t, http.MethodPost,
			fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwB),
			nil, map[string]any{
				"name":         uniqueName("co-roles-foreign"),
				"routing_mode": "role_based",
				"roles":        []string{foreignRole},
			},
		)
		require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
		assert.Equal(t, "validation_failed", body["error"])
	})

	t.Run("nonexistent role is rejected", func(t *testing.T) {
		gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-roles-gw-404")})

		status, body := sendRequest(t, http.MethodPost,
			fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
			nil, map[string]any{
				"name":         uniqueName("co-roles-404"),
				"routing_mode": "role_based",
				"roles":        []string{uuid.NewString()},
			},
		)
		require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
		assert.Equal(t, "validation_failed", body["error"])
	})

	t.Run("malformed role id is rejected", func(t *testing.T) {
		gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-roles-gw-bad")})

		status, body := sendRequest(t, http.MethodPost,
			fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
			nil, map[string]any{
				"name":         uniqueName("co-roles-bad"),
				"routing_mode": "role_based",
				"roles":        []string{"not-a-uuid"},
			},
		)
		require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
		assert.Equal(t, "validation_failed", body["error"])
	})

	t.Run("roles with inline routing are rejected", func(t *testing.T) {
		gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-roles-gw-inline")})
		roleID := CreateRole(t, gwID, map[string]any{"name": uniqueName("co-role-inline")})

		status, body := sendRequest(t, http.MethodPost,
			fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
			nil, map[string]any{
				"name":  uniqueName("co-roles-inline"),
				"roles": []string{roleID},
			},
		)
		require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
		assert.Equal(t, "validation_failed", body["error"])
	})
}

func TestCreateConsumer_InvalidBody(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-badbody-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, "not-an-object",
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateConsumer_TypeDefaultsToLLM(t *testing.T) {
	defer Track(t, "CreateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-deftype-gw")})
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
			gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-" + ty + "-gw")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-badtype-gw")})

	payload := validConsumerPayload(uniqueName("co-badtype"))
	payload["type"] = "foo"

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
