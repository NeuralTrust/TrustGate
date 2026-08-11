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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-gw")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-keep-gw")})
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

	got := idSet(t, getConsumer(t, gwID, coID), "registry_ids")
	require.Len(t, got, 2, "update must not drop associations")
	assert.Contains(t, got, be1)
	assert.Contains(t, got, be2)
}

// TestUpdateConsumer_SetsModelPolicies attaches a registry, then binds a model
// policy through an update and asserts it is persisted and returned.
func TestUpdateConsumer_SetsModelPolicies(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-mp-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-mp-be")))
	name := uniqueName("co-upd-mp")
	coID := CreateConsumerWithRegistries(t, gwID, name, beID)

	payload := validConsumerPayload(name)
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

// TestUpdateConsumer_RejectsModelPolicyForUnassociatedRegistry ensures a model
// policy can only reference a registry already attached to the consumer.
func TestUpdateConsumer_RejectsModelPolicyForUnassociatedRegistry(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-mp-unassoc-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-mp-unassoc-be")))
	name := uniqueName("co-upd-mp-unassoc")
	coID := CreateConsumer(t, gwID, validConsumerPayload(name)) // registry NOT attached

	payload := validConsumerPayload(name)
	payload["model_policies"] = []map[string]any{
		{"registry_id": beID, "allowed": []string{"gpt-4o-mini"}},
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-partial-gw")})
	name := uniqueName("co-upd-partial")
	coID := CreateConsumer(t, gwID, validConsumerPayload(name))
	expectedSlug := ConsumerSlug(t, coID)

	renamed := uniqueName("co-upd-partial-to")
	url := fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"name": renamed})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, renamed, body["name"])

	status, body = sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, renamed, body["name"])
	assert.Equal(t, expectedSlug, body["slug"], "slug must be preserved on a partial update")
}

func TestUpdateConsumer_Partial_EmptyTypePreservesExisting(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-empty-type-gw")})
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

// TestUpdateConsumer_SwitchRoleBasedToInlineWithRegistries covers the routing
// switch a UI performs in one step: the registry links cannot be created before
// the consumer leaves role_based mode, so they travel in the update body.
func TestUpdateConsumer_SwitchRoleBasedToInlineWithRegistries(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-rb2inline-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-rb2inline-be")))
	roleID := CreateRole(t, gwID, map[string]any{"name": uniqueName("co-upd-rb2inline-role")})
	name := uniqueName("co-upd-rb2inline")
	coID := CreateConsumer(t, gwID, map[string]any{
		"name":         name,
		"routing_mode": "role_based",
		"roles":        []string{roleID},
	})

	// Attaching through the association endpoint is what fails while the
	// consumer is still role_based.
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s/registries/%s", AdminURL, gwID, coID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)

	status, body = sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, map[string]any{
			"name":           name,
			"routing_mode":   "inline",
			"registries":     []map[string]any{{"id": beID, "weight": 40}},
			"model_policies": []map[string]any{{"registry_id": beID, "default": "gpt-4o-mini"}},
		},
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	got := getConsumer(t, gwID, coID)
	assert.Equal(t, "inline", got["routing_mode"])
	assert.Empty(t, idSet(t, got, "role_ids"), "roles must be dropped on the switch to inline")
	registries := idSet(t, got, "registry_ids")
	require.Len(t, registries, 1)
	assert.Contains(t, registries, beID)
}

// TestUpdateConsumer_RegistriesReplaceAssociationSet asserts the field is a full
// replacement: registries missing from the list are detached.
func TestUpdateConsumer_RegistriesReplaceAssociationSet(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-replace-gw")})
	be1 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-replace-be1")))
	be2 := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-replace-be2")))
	name := uniqueName("co-upd-replace")
	coID := CreateConsumerWithRegistries(t, gwID, name, be1, be2)

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, map[string]any{"name": name, "registries": []map[string]any{{"id": be2}}},
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	got := idSet(t, getConsumer(t, gwID, coID), "registry_ids")
	require.Len(t, got, 1)
	assert.Contains(t, got, be2)
}

// TestUpdateConsumer_RejectsRegistriesInRoleBasedMode keeps the invariant that a
// role_based consumer never holds registry links.
func TestUpdateConsumer_RejectsRegistriesInRoleBasedMode(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-rb-reg-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-upd-rb-reg-be")))
	name := uniqueName("co-upd-rb-reg")
	coID := CreateConsumer(t, gwID, validConsumerPayload(name))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, map[string]any{
			"name":         name,
			"routing_mode": "role_based",
			"registries":   []map[string]any{{"id": beID}},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

// TestUpdateConsumer_RejectsRegistryFromAnotherGateway keeps the association set
// inside the gateway boundary.
func TestUpdateConsumer_RejectsRegistryFromAnotherGateway(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-xgw-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-xgw-b")})
	foreign := CreateRegistry(t, gwB, validRegistryPayload(uniqueName("co-upd-xgw-be")))
	name := uniqueName("co-upd-xgw")
	coID := CreateConsumer(t, gwA, validConsumerPayload(name))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwA, coID),
		nil, map[string]any{"name": name, "registries": []map[string]any{{"id": foreign}}},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateConsumer_NotFound(t *testing.T) {
	defer Track(t, "UpdateConsumer")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-missing-gw")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-val-gw")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-conflict-gw")})
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
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("co-upd-bad-co-gw")})

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/not-a-uuid", AdminURL, gwID),
		nil,
		validConsumerPayload(uniqueName("co-upd-bad-co")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
