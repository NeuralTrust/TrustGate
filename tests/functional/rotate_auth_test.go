//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotateAuth_MintsANewSecretAndKeepsTheAttachment(t *testing.T) {
	defer Track(t, "RotateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-rotate")})
	authID, firstKey := CreateAPIKeyAuth(t, gwID, uniqueName("api-key-rotate"))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("auth-rotate-cons")))
	AttachAuth(t, gwID, coID, authID)

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s/rotate", AdminURL, gwID, authID), nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	rotated, ok := body["api_key"].(string)
	require.True(t, ok, "rotate must surface the new api_key: %v", body)
	assert.True(t, strings.HasPrefix(rotated, "ag_"), "rotated key must carry the ag_ prefix: %q", rotated)
	assert.NotEqual(t, firstKey, rotated, "rotate must replace the secret")
	assert.Equal(t, authID, body["id"], "rotate keeps the auth: consumers hold its id")
	assert.Equal(t, rotated[:8], body["key_prefix"])
	assert.Equal(t, rotated[len(rotated)-4:], body["key_suffix"])

	// What the auth is attached to is untouched — that is the whole point of
	// rotating rather than revoking and issuing again.
	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID), nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Contains(t, fmt.Sprintf("%v", body["auth_ids"]), authID)

	// And the key is not readable again afterwards.
	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, authID), nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Empty(t, body["api_key"], "the secret is returned once, by the rotation that minted it")
}

func TestRotateAuth_RefusesAnIdentityProvider(t *testing.T) {
	defer Track(t, "RotateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-rotate-idp")})
	authID := CreateAuth(t, gwID, map[string]any{
		"name": uniqueName("oauth-rotate"),
		"type": "oauth2",
		"config": map[string]any{
			"oauth2": map[string]any{
				"issuer":    "https://issuer.example.com",
				"audiences": []string{"gateway"},
				"jwks_url":  "https://issuer.example.com/.well-known/jwks.json",
			},
		},
	})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s/rotate", AdminURL, gwID, authID), nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "only api keys carry a secret to rotate, body=%v", body)
}

func TestRotateAuth_NotFound(t *testing.T) {
	defer Track(t, "RotateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-rotate-404")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s/rotate", AdminURL, gwID, uuid.NewString()), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}
