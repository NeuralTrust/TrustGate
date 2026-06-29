//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateGateway_Success(t *testing.T) {
	defer Track(t, "CreateGateway")()
	slug := uniqueName("create-ok")
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, map[string]any{
		"slug": slug,
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
		"slug": slug,
	})
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreateGateway_ValidationEmptySlug(t *testing.T) {
	defer Track(t, "CreateGateway")()
	status, body := sendRequest(t, http.MethodPost, AdminURL+"/v1/gateways", nil, map[string]any{
		"slug": "",
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
