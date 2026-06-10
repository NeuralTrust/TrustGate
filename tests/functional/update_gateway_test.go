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

func TestUpdateGateway_Success(t *testing.T) {
	defer Track(t, "UpdateGateway")()
	original := uniqueName("upd-from")
	id := CreateGateway(t, map[string]any{"name": original})

	updated := uniqueName("upd-to")
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, id),
		nil,
		map[string]any{
			"name":   updated,
			"status": "inactive",
		},
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, updated, body["name"])
	assert.Equal(t, "inactive", body["status"])

	// Re-read to make sure the change was persisted, not just echoed.
	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, id), nil, nil,
	)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, updated, body["name"])
	assert.Equal(t, "inactive", body["status"])
}

func TestUpdateGateway_Partial(t *testing.T) {
	defer Track(t, "UpdateGateway")()
	id := CreateGateway(t, map[string]any{"name": uniqueName("upd-partial")})
	url := fmt.Sprintf("%s/v1/gateways/%s", AdminURL, id)

	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"status": "inactive"})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, "inactive", body["status"])

	renamed := uniqueName("upd-partial-to")
	status, body = sendRequest(t, http.MethodPut, url, nil, map[string]any{"name": renamed})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, renamed, body["name"])

	status, body = sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, renamed, body["name"])
	assert.Equal(t, "inactive", body["status"], "status must be preserved on a partial update")
}

func TestUpdateGateway_NotFound(t *testing.T) {
	defer Track(t, "UpdateGateway")()
	missing := uuid.NewString()
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, missing), nil,
		map[string]any{"name": uniqueName("upd-missing"), "status": "active"},
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestUpdateGateway_ValidationEmptyName(t *testing.T) {
	defer Track(t, "UpdateGateway")()
	id := CreateGateway(t, map[string]any{"name": uniqueName("upd-val")})

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, id), nil,
		map[string]any{"name": "", "status": "active"},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateGateway_NameConflict(t *testing.T) {
	defer Track(t, "UpdateGateway")()
	a := uniqueName("upd-a")
	b := uniqueName("upd-b")
	_ = CreateGateway(t, map[string]any{"name": a})
	bID := CreateGateway(t, map[string]any{"name": b})

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, bID), nil,
		map[string]any{"name": a, "status": "active"},
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}
