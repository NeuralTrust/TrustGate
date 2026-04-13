package functional_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakeSABase64(t *testing.T) string {
	t.Helper()
	sa := map[string]string{
		"type":                        "service_account",
		"project_id":                  "test-project",
		"private_key_id":              "key123",
		"private_key":                 "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH...fake...key\n-----END RSA PRIVATE KEY-----\n",
		"client_email":                "test@test-project.iam.gserviceaccount.com",
		"client_id":                   "123456789",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com",
	}
	raw, err := json.Marshal(sa)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

func vertexTarget(overrides map[string]interface{}) map[string]interface{} {
	target := map[string]interface{}{
		"weight":        1,
		"provider":      "vertex",
		"default_model": "gemini-2.0-flash",
		"models":        []string{"gemini-2.0-flash", "gemini-2.5-pro"},
		"provider_options": map[string]interface{}{
			"project":  "my-gcp-project",
			"location": "us-central1",
		},
	}
	for k, v := range overrides {
		target[k] = v
	}
	return target
}

func vertexUpstreamPayload(name string, targets []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"name":      name,
		"algorithm": "round-robin",
		"targets":   targets,
	}
}

func TestCreateUpstreamVertex(t *testing.T) {
	defer RunTest(t, "CreateUpstreamVertex", time.Now())()

	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "Vertex Upstream Test Gateway",
		"subdomain": fmt.Sprintf("vertex-test-%d", time.Now().UnixNano()),
	})

	t.Run("vertex with api_key credentials", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex API Key", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"credentials": map[string]interface{}{
					"api_key": "ya29.fake-access-token",
				},
			}),
		})

		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		require.Equal(t, http.StatusCreated, status, "response: %v", resp)
		assert.NotEmpty(t, resp["id"])
		assert.Equal(t, "Vertex API Key", resp["name"])

		targets, ok := resp["targets"].([]interface{})
		require.True(t, ok)
		assert.Len(t, targets, 1)
	})

	t.Run("vertex with oauth2 client_credentials", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex OAuth2", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"auth": map[string]interface{}{
					"type": "oauth2",
					"oauth": map[string]interface{}{
						"token_url":      "https://oauth2.googleapis.com/token",
						"grant_type":     "client_credentials",
						"client_id":      "my-client-id",
						"client_secret":  "my-client-secret",
						"scopes":         []string{"https://www.googleapis.com/auth/cloud-platform"},
						"use_basic_auth": false,
					},
				},
			}),
		})

		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		require.Equal(t, http.StatusCreated, status, "response: %v", resp)
		assert.NotEmpty(t, resp["id"])

		targets, ok := resp["targets"].([]interface{})
		require.True(t, ok)
		require.Len(t, targets, 1)

		tgt := targets[0].(map[string]interface{})
		auth, ok := tgt["auth"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "oauth2", auth["type"])
	})

	t.Run("vertex with gcp_service_account inline", func(t *testing.T) {
		saB64 := fakeSABase64(t)
		payload := vertexUpstreamPayload("Vertex SA Inline", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"auth": map[string]interface{}{
					"type":                "gcp_service_account",
					"gcp_service_account": saB64,
				},
			}),
		})

		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		require.Equal(t, http.StatusCreated, status, "response: %v", resp)
		assert.NotEmpty(t, resp["id"])

		targets, ok := resp["targets"].([]interface{})
		require.True(t, ok)
		require.Len(t, targets, 1)

		tgt := targets[0].(map[string]interface{})
		auth, ok := tgt["auth"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "gcp_service_account", auth["type"])
		gcpSA, ok := auth["gcp_service_account"].(string)
		assert.True(t, ok)
		assert.NotEqual(t, saB64, gcpSA, "SA should be encrypted, not stored as plaintext")
		assert.NotEmpty(t, gcpSA)
	})

	t.Run("vertex with gcp_service_account empty and no env fallback -> 400", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex SA Env Fallback", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"auth": map[string]interface{}{
					"type": "gcp_service_account",
				},
			}),
		})

		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
		errMsg, _ := resp["error"].(string)
		assert.Contains(t, errMsg, "GOOGLE_APPLICATION_CREDENTIALS")
	})

	t.Run("vertex with invalid base64 service account -> 400", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex SA Invalid B64", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"auth": map[string]interface{}{
					"type":                "gcp_service_account",
					"gcp_service_account": "not-valid-base64!!!",
				},
			}),
		})

		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
		errMsg, _ := resp["error"].(string)
		assert.Contains(t, errMsg, "invalid")
	})

	t.Run("vertex with SA missing required fields -> 400", func(t *testing.T) {
		incomplete := map[string]string{
			"type":       "service_account",
			"project_id": "test-project",
		}
		raw, err := json.Marshal(incomplete)
		require.NoError(t, err)
		b64 := base64.StdEncoding.EncodeToString(raw)

		payload := vertexUpstreamPayload("Vertex SA Incomplete", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"auth": map[string]interface{}{
					"type":                "gcp_service_account",
					"gcp_service_account": b64,
				},
			}),
		})

		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
		errMsg, _ := resp["error"].(string)
		assert.Contains(t, errMsg, "missing required field")
	})

	t.Run("vertex missing provider_options -> 400", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex No Options", []map[string]interface{}{
			{
				"weight":        1,
				"provider":      "vertex",
				"default_model": "gemini-2.0-flash",
				"models":        []string{"gemini-2.0-flash"},
				"credentials": map[string]interface{}{
					"api_key": "ya29.fake",
				},
			},
		})

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("vertex missing project in provider_options -> 400", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex No Project", []map[string]interface{}{
			{
				"weight":        1,
				"provider":      "vertex",
				"default_model": "gemini-2.0-flash",
				"models":        []string{"gemini-2.0-flash"},
				"credentials": map[string]interface{}{
					"api_key": "ya29.fake",
				},
				"provider_options": map[string]interface{}{
					"location": "us-central1",
				},
			},
		})

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("vertex missing location in provider_options -> 400", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex No Location", []map[string]interface{}{
			{
				"weight":        1,
				"provider":      "vertex",
				"default_model": "gemini-2.0-flash",
				"models":        []string{"gemini-2.0-flash"},
				"credentials": map[string]interface{}{
					"api_key": "ya29.fake",
				},
				"provider_options": map[string]interface{}{
					"project": "my-gcp-project",
				},
			},
		})

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("vertex with unknown provider_options key -> 400", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex Unknown Key", []map[string]interface{}{
			{
				"weight":        1,
				"provider":      "vertex",
				"default_model": "gemini-2.0-flash",
				"models":        []string{"gemini-2.0-flash"},
				"credentials": map[string]interface{}{
					"api_key": "ya29.fake",
				},
				"provider_options": map[string]interface{}{
					"project":  "my-gcp-project",
					"location": "us-central1",
					"foo":      "bar",
				},
			},
		})

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("vertex with custom version in provider_options", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex Custom Version", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"credentials": map[string]interface{}{
					"api_key": "ya29.fake-token",
				},
				"provider_options": map[string]interface{}{
					"project":  "my-gcp-project",
					"location": "europe-west1",
					"version":  "v1beta1",
				},
			}),
		})

		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		require.Equal(t, http.StatusCreated, status, "response: %v", resp)
		assert.NotEmpty(t, resp["id"])
	})

	t.Run("vertex multi-target with mixed auth types", func(t *testing.T) {
		saB64 := fakeSABase64(t)
		payload := vertexUpstreamPayload("Vertex Multi Auth", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"credentials": map[string]interface{}{
					"api_key": "ya29.token-1",
				},
				"weight": 2,
			}),
			vertexTarget(map[string]interface{}{
				"auth": map[string]interface{}{
					"type":                "gcp_service_account",
					"gcp_service_account": saB64,
				},
				"weight": 1,
			}),
		})

		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		require.Equal(t, http.StatusCreated, status, "response: %v", resp)
		assert.NotEmpty(t, resp["id"])

		targets, ok := resp["targets"].([]interface{})
		require.True(t, ok)
		assert.Len(t, targets, 2)
	})

	t.Run("vertex target must not have path", func(t *testing.T) {
		payload := vertexUpstreamPayload("Vertex With Path", []map[string]interface{}{
			vertexTarget(map[string]interface{}{
				"path": "/v1/chat/completions",
				"credentials": map[string]interface{}{
					"api_key": "ya29.fake",
				},
			}),
		})

		status, _ := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/upstreams", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}
