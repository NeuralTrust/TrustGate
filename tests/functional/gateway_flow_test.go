package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGatewayFlowPolicies(t *testing.T) {

	t.Run("happy path with two policies", func(t *testing.T) {
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Gateway Flow 1",
			"subdomain": fmt.Sprintf("gw-flow-1-%d", time.Now().UnixNano()),
		})

		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "Flow Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     8081,
					"protocol": "http",
					"path":     "/__/ping",
					"weight":   100,
					"priority": 1,
				},
			},
		})

		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "Flow Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})

		// two rules
		status, resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, map[string]interface{}{
			"path":       "/flow-1a",
			"name":       "flow-1a",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})
		assert.Equal(t, http.StatusCreated, status)
		ruleID1, ok := resp["id"].(string)
		assert.True(t, ok, "rule ID should be a string")
		assert.NotEmpty(t, ruleID1)

		status, resp = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, map[string]interface{}{
			"path":       "/flow-1b",
			"name":       "flow-1b",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})
		assert.Equal(t, http.StatusCreated, status)
		ruleID2, ok := resp["id"].(string)
		assert.True(t, ok, "rule ID should be a string")
		assert.NotEmpty(t, ruleID2)

		// create API key with both policies via new IAM endpoint
		apiKeyPayload := map[string]interface{}{
			"name":         "Benchmark Key",
			"expires_at":   "2066-01-01T00:00:00Z",
			"subject_type": "gateway",
			"subject":      gatewayID,
			"policies":     []string{ruleID1, ruleID2},
		}
		status, akResp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/iam/api-keys", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, apiKeyPayload)
		assert.Equal(t, http.StatusCreated, status)
		apiKey, ok := akResp["key"].(string)
		assert.True(t, ok, "API key should be a string")
		assert.NotEmpty(t, apiKey)

		// call both routes through proxy -> 200
		for _, p := range []string{"/flow-1a", "/flow-1b"} {
			req, err := http.NewRequest(http.MethodGet, ProxyUrl+p, nil)
			assert.NoError(t, err)
			req.Header.Set("X-TG-API-Key", apiKey)
			resp, err := http.DefaultClient.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			_ = resp.Body.Close()
		}
	})

	t.Run("invalid policy id in list fails", func(t *testing.T) {
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Gateway Flow 2",
			"subdomain": fmt.Sprintf("gw-flow-2-%d", time.Now().UnixNano()),
		})
		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "Flow Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     8081,
					"protocol": "http",
					"path":     "/__/ping",
					"weight":   100,
					"priority": 1,
				},
			},
		})
		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "Flow Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})
		status, r := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, map[string]interface{}{
			"path":       "/flow-2",
			"name":       "flow-2",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})
		assert.Equal(t, http.StatusCreated, status)
		ruleID, ok := r["id"].(string)
		assert.True(t, ok, "rule ID should be a string")
		assert.NotEmpty(t, ruleID)

		fake := uuid.New().String()
		payload := map[string]interface{}{
			"name":         "Benchmark Key",
			"expires_at":   "2066-01-01T00:00:00Z",
			"subject_type": "gateway",
			"subject":      gatewayID,
			"policies":     []string{ruleID, fake},
		}
		status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/iam/api-keys", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("policy subject type with gateway subject should fail", func(t *testing.T) {
		gatewayID := CreateGateway(t, map[string]interface{}{
			"name":      "Gateway Flow 3",
			"subdomain": fmt.Sprintf("gw-flow-3-%d", time.Now().UnixNano()),
		})
		upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
			"name":      "Flow Upstream",
			"algorithm": "round-robin",
			"targets": []map[string]interface{}{
				{
					"host":     "localhost",
					"port":     8081,
					"protocol": "http",
					"path":     "/__/ping",
					"weight":   100,
					"priority": 1,
				},
			},
		})
		serviceID := CreateService(t, gatewayID, map[string]interface{}{
			"name":        "Flow Service",
			"type":        "upstream",
			"upstream_id": upstreamID,
		})
		status, r := sendRequest(t, http.MethodPost, fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, map[string]interface{}{
			"path":       "/flow-3",
			"name":       "flow-3",
			"service_id": serviceID,
			"methods":    []string{"GET"},
		})
		assert.Equal(t, http.StatusCreated, status)
		ruleID, ok := r["id"].(string)
		assert.True(t, ok, "rule ID should be a string")
		assert.NotEmpty(t, ruleID)

		payload := map[string]interface{}{
			"name":         "Benchmark Key",
			"expires_at":   "2066-01-01T00:00:00Z",
			"subject_type": "policy",
			"subject":      gatewayID,
			"policies":     []string{ruleID},
		}
		status, _ = sendRequest(t, http.MethodPost, fmt.Sprintf("%s/iam/api-keys", AdminUrl), map[string]string{
			"Authorization": fmt.Sprintf("Bearer %s", AdminToken),
		}, payload)
		assert.Equal(t, http.StatusBadRequest, status)
	})
}
