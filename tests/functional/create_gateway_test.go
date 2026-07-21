//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stampedFreeEntitlements() map[string]any {
	return map[string]any{
		"tier":            "free",
		"burst_per_min":   60,
		"quota_per_month": 10000,
		"max_instances":   5,
	}
}

func TestCreateGateway_Success(t *testing.T) {
	defer Track(t, "CreateGateway")()
	slug := uniqueName("create-ok")
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, map[string]any{
		"slug":         slug,
		"tenant_id":    "functional-tenant",
		"entitlements": stampedFreeEntitlements(),
	})

	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, slug, body["slug"])
	assert.Equal(t, "active", body["status"])
	assert.NotEmpty(t, body["id"])
	assert.NotEmpty(t, body["created_at"])
	assert.NotEmpty(t, body["updated_at"])
}

func TestCreateGateway_Conflict(t *testing.T) {
	defer Track(t, "CreateGateway")()
	slug := uniqueName("create-dup")
	_ = CreateGateway(t, map[string]any{"slug": slug})

	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, map[string]any{
		"slug":         slug,
		"tenant_id":    "functional-tenant",
		"entitlements": stampedFreeEntitlements(),
	})
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreateGateway_GeneratesSlugWhenEmpty(t *testing.T) {
	defer Track(t, "CreateGateway")()
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, map[string]any{
		"slug":         "",
		"tenant_id":    "functional-tenant",
		"entitlements": stampedFreeEntitlements(),
	})
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.NotEmpty(t, body["slug"])
	assert.Equal(t, "active", body["status"])
	assert.NotEmpty(t, body["id"])
}

func TestCreateGateway_GeneratesSlugWhenOmitted(t *testing.T) {
	defer Track(t, "CreateGateway")()
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, map[string]any{
		"tenant_id":    "functional-tenant",
		"entitlements": stampedFreeEntitlements(),
	})
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.NotEmpty(t, body["slug"])
	assert.Equal(t, "active", body["status"])
}

func TestCreateGateway_PlatformAdmin_MissingTenantID_Rejected(t *testing.T) {
	defer Track(t, "CreateGateway")()
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, map[string]any{
		"slug": uniqueName("no-tenant"),
	})
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateGateway_PlatformAdmin_MissingEntitlements_Rejected(t *testing.T) {
	defer Track(t, "CreateGateway")()
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, map[string]any{
		"slug":      uniqueName("no-ents"),
		"tenant_id": "functional-tenant",
	})
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateGateway_InvalidBody(t *testing.T) {
	defer Track(t, "CreateGateway")()
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, "not-an-object")
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
