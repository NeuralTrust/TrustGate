//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuth_Success_GeneratesKey(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-create")})
	name := uniqueName("api-key")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		validAuthPayload(name),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "api_key", body["type"])
	assert.Equal(t, true, body["enabled"])
	assert.NotEmpty(t, body["id"])

	// The plaintext key is generated server-side and returned exactly once.
	key, ok := body["api_key"].(string)
	require.True(t, ok, "create must surface the generated api_key: %v", body)
	assert.True(t, strings.HasPrefix(key, "ag_"), "generated key must carry the ag_ prefix: %q", key)
	assert.Equal(t, key[:8], body["key_prefix"], "key_prefix must match the head of the issued key")
	assert.Equal(t, key[len(key)-4:], body["key_suffix"], "key_suffix must match the tail of the issued key")

	// The secret never lives inside config: api_key auth carries no config block.
	cfg, ok := body["config"].(map[string]any)
	require.True(t, ok, "config missing: %v", body)
	_, hasAPIKeyCfg := cfg["api_key"]
	assert.False(t, hasAPIKeyCfg, "api_key auth must not echo a config.api_key block: %v", cfg)
}

func TestCreateAuth_OAuth2(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-oauth")})
	name := uniqueName("oauth")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{
			"name": name,
			"type": "oauth2",
			"config": map[string]any{
				"oauth2": map[string]any{
					"issuer":        "https://issuer.example.com",
					"audiences":     []string{"gateway"},
					"jwks_url":      "https://issuer.example.com/.well-known/jwks.json",
					"client_secret": "topsecretclientvalue",
				},
			},
		},
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	cfg, _ := body["config"].(map[string]any)
	oauth, ok := cfg["oauth2"].(map[string]any)
	require.True(t, ok, "oauth2 config missing: %v", cfg)
	assert.Equal(t, "https://issuer.example.com", oauth["issuer"])
	assert.Equal(t, "***alue", oauth["client_secret"], "client_secret must be masked with a short tail")
}

func TestCreateAuth_LegacyOIDCAliasIsCanonicalized(t *testing.T) {
	defer Track(t, "CreateAuth")()
	config := map[string]any{
		"issuer":             "https://issuer.example.com",
		"audiences":          []string{"gateway"},
		"jwks_url":           "https://issuer.example.com/.well-known/jwks.json",
		"public_keys":        []string{"-----BEGIN PUBLIC KEY-----"},
		"required_scopes":    []string{"api.read"},
		"allowed_algorithms": []string{"RS256"},
		"subject_claim":      "oid",
	}

	cases := []struct {
		name      string
		authType  string
		configKey string
	}{
		{name: "legacy type with legacy payload", authType: "oidc", configKey: "oidc"},
		{name: "legacy type with canonical payload", authType: "oidc", configKey: "oauth2"},
		{name: "canonical type with legacy payload", authType: "oauth2", configKey: "oidc"},
		{name: "canonical type with canonical payload", authType: "oauth2", configKey: "oauth2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-oidc-alias")})
			status, body := sendRequest(t, http.MethodPost,
				fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
				map[string]any{
					"name":   uniqueName("oidc-alias"),
					"type":   tc.authType,
					"config": map[string]any{tc.configKey: config},
				},
			)
			require.Equal(t, http.StatusCreated, status, "body=%v", body)
			assertCanonicalOAuth2Auth(t, body)

			id, ok := body["id"].(string)
			require.True(t, ok, "create response missing id: %v", body)
			status, body = sendRequest(t, http.MethodGet,
				fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil, nil,
			)
			require.Equal(t, http.StatusOK, status, "body=%v", body)
			assertCanonicalOAuth2Auth(t, body)
		})
	}
}

func assertCanonicalOAuth2Auth(t *testing.T, body map[string]any) {
	t.Helper()
	assert.Equal(t, "oauth2", body["type"], "the legacy type must be canonicalized: %v", body)

	cfg, ok := body["config"].(map[string]any)
	require.True(t, ok, "config missing: %v", body)
	_, hasLegacy := cfg["oidc"]
	assert.False(t, hasLegacy, "the response must not echo a config.oidc block: %v", cfg)

	oauth, ok := cfg["oauth2"].(map[string]any)
	require.True(t, ok, "oauth2 config missing: %v", cfg)
	assert.Equal(t, "https://issuer.example.com", oauth["issuer"])
	assert.Equal(t, "https://issuer.example.com/.well-known/jwks.json", oauth["jwks_url"])
	assert.Equal(t, "oid", oauth["subject_claim"])
	assert.Equal(t, []any{"gateway"}, oauth["audiences"])
	assert.Equal(t, []any{"-----BEGIN PUBLIC KEY-----"}, oauth["public_keys"])
	assert.Equal(t, []any{"api.read"}, oauth["required_scopes"])
	assert.Equal(t, []any{"RS256"}, oauth["allowed_algorithms"])
}

func TestCreateAuth_LegacyOIDCAliasRejectsProtocolScopes(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-oidc-scope")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{
			"name": uniqueName("oidc-scope"),
			"type": "oidc",
			"config": map[string]any{
				"oidc": map[string]any{
					"issuer":          "https://issuer.example.com",
					"audiences":       []string{"gateway"},
					"jwks_url":        "https://issuer.example.com/.well-known/jwks.json",
					"required_scopes": []string{"openid"},
				},
			},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
	message, _ := body["message"].(string)
	assert.Contains(t, message, "openid", "body=%v", body)
}

func TestCreateAuth_RejectsTwoConfigPayloads(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-two-payloads")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{
			"name": uniqueName("two-payloads"),
			"type": "oauth2",
			"config": map[string]any{
				"oauth2": map[string]any{
					"issuer":    "https://issuer.example.com",
					"audiences": []string{"gateway"},
					"jwks_url":  "https://issuer.example.com/.well-known/jwks.json",
				},
				"oidc": map[string]any{
					"issuer":    "https://other.example.com",
					"audiences": []string{"gateway"},
					"jwks_url":  "https://other.example.com/.well-known/jwks.json",
				},
			},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
	message, _ := body["message"].(string)
	assert.Contains(t, message, "exactly one config payload", "body=%v", body)
}

func TestCreateAuth_OAuth2RequiresAudiences(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-oauth-aud")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{
			"name": uniqueName("oauth"),
			"type": "oauth2",
			"config": map[string]any{
				"oauth2": map[string]any{
					"issuer":   "https://issuer.example.com",
					"jwks_url": "https://issuer.example.com/.well-known/jwks.json",
				},
			},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateAuth_DuplicateNameAllowed(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-dup")})
	name := uniqueName("api-key")
	firstID := CreateAuth(t, gwID, validAuthPayload(name))

	// Auth names are labels only — credentials resolve by id / key_hash, so two
	// api_key auths on the same gateway may share a display name.
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		validAuthPayload(name),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	secondID, ok := body["id"].(string)
	require.True(t, ok, "create auth response missing id: %v", body)
	assert.NotEqual(t, firstID, secondID)
	assert.Equal(t, name, body["name"])
	assert.NotEmpty(t, body["api_key"])
}

func TestCreateAuth_ConflictsWithRowStoredAsOIDC(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-stored-oidc-conflict")})
	const issuer = "https://conflict.example.com"
	SeedStoredOIDCAuth(t, gwID, uniqueName("stored-oidc"), issuer, []string{"gateway"})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{
			"name": uniqueName("native-oauth2"),
			"type": "oauth2",
			"config": map[string]any{
				"oauth2": map[string]any{
					"issuer":    issuer,
					"audiences": []string{"gateway"},
					"jwks_url":  issuer + "/.well-known/jwks.json",
				},
			},
		},
	)
	require.Equal(t, http.StatusConflict, status,
		"a row stored as oidc must still be seen by the duplicate guard: body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreateAuth_InvalidType(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-val")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{"name": uniqueName("bad"), "type": "bogus"},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateAuth_ValidationEmptyName(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-noname")})

	payload := validAuthPayload("")
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
