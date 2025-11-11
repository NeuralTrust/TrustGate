package firewall_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOpenAIFirewallClient(t *testing.T) {
	logger := logrus.New()
	t.Run("Creates client successfully", func(t *testing.T) {
		client := firewall.NewOpenAIFirewallClient(logger)

		assert.NotNil(t, client)
		assert.IsType(t, &firewall.OpenAIFirewallClient{}, client)
	})
}

func TestOpenAIFirewallClient_DetectJailbreak(t *testing.T) {
	t.Run("Success with output_text", func(t *testing.T) {
		expectedResponse := firewall.JailbreakResponse{
			Scores: firewall.JailbreakScores{
				MaliciousPrompt: 0.8,
			},
		}

		responseJSON, err := json.Marshal(expectedResponse)
		require.NoError(t, err)
		openAIResponse := map[string]interface{}{
			"output_text": string(responseJSON),
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

			var requestBody map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&requestBody) //nolint:errcheck
			assert.Equal(t, "gpt-4o-mini", requestBody["model"])
			assert.Equal(t, float64(0), requestBody["temperature"])

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(openAIResponse) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		// Override the endpoint for testing
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test prompt"},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Equal(t, expectedResponse.Scores.MaliciousPrompt, result[0].Scores.MaliciousPrompt)
	})

	t.Run("Success with output array", func(t *testing.T) {
		expectedResponse := firewall.JailbreakResponse{
			Scores: firewall.JailbreakScores{
				MaliciousPrompt: 0.7,
			},
		}

		responseJSON, err := json.Marshal(expectedResponse)
		require.NoError(t, err)
		openAIResponse := map[string]interface{}{
			"output": []map[string]interface{}{
				{
					"content": []map[string]interface{}{
						{
							"type": "output_text",
							"text": string(responseJSON),
						},
					},
				},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(openAIResponse) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test prompt"},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Equal(t, expectedResponse.Scores.MaliciousPrompt, result[0].Scores.MaliciousPrompt)
	})

	t.Run("Empty input", func(t *testing.T) {
		client := firewall.NewOpenAIFirewallClient(logrus.New())

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{""},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "input cannot be empty")
	})

	t.Run("Empty API key", func(t *testing.T) {
		client := firewall.NewOpenAIFirewallClient(logrus.New())

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "",
			},
		}
		content := firewall.Content{
			Input: []string{"test prompt"},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "openai api key is required")
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("invalid json")) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test prompt"},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to parse response")
	})

	t.Run("HTTP error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "bad request"}`)) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test prompt"},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "firewall service call failed: status 400")
	})

	t.Run("Empty response text", func(t *testing.T) {
		openAIResponse := map[string]interface{}{
			"output_text": "",
			"output":      []map[string]interface{}{},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(openAIResponse) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test prompt"},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "response contained no text output")
	})

	t.Run("Context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test prompt"},
		}

		result, err := client.DetectJailbreak(ctx, content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestOpenAIFirewallClient_DetectToxicity(t *testing.T) {
	t.Run("Success with output_text", func(t *testing.T) {
		expectedResponse := firewall.ToxicityResponse{
			CategoryScores: map[string]float64{
				"toxic_prompt": 0.9,
			},
		}

		responseJSON, err := json.Marshal(expectedResponse)
		require.NoError(t, err)
		openAIResponse := map[string]interface{}{
			"output_text": string(responseJSON),
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(openAIResponse) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test content"},
		}

		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Equal(t, expectedResponse.CategoryScores["toxic_prompt"], result[0].CategoryScores["toxic_prompt"])
	})

	t.Run("Success with output array", func(t *testing.T) {
		expectedResponse := firewall.ToxicityResponse{
			CategoryScores: map[string]float64{
				"toxic_prompt": 0.6,
			},
		}

		responseJSON, err := json.Marshal(expectedResponse)
		require.NoError(t, err)
		openAIResponse := map[string]interface{}{
			"output": []map[string]interface{}{
				{
					"content": []map[string]interface{}{
						{
							"type": "output_text",
							"text": string(responseJSON),
						},
					},
				},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(openAIResponse) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test content"},
		}

		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Equal(t, expectedResponse.CategoryScores["toxic_prompt"], result[0].CategoryScores["toxic_prompt"])
	})

	t.Run("Empty input", func(t *testing.T) {
		client := firewall.NewOpenAIFirewallClient(logrus.New())

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{""},
		}

		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "input cannot be empty")
	})

	t.Run("Empty API key", func(t *testing.T) {
		client := firewall.NewOpenAIFirewallClient(logrus.New())

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "",
			},
		}
		content := firewall.Content{
			Input: []string{"test content"},
		}

		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "openai api key is required")
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("invalid json")) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test content"},
		}

		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to parse response")
	})

	t.Run("HTTP error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "internal server error"}`)) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"test content"},
		}

		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "firewall service call failed: status 500")
	})
}

func TestOpenAIFirewallClient_MultipleInputs(t *testing.T) {
	t.Run("Multiple inputs joined", func(t *testing.T) {
		expectedResponse := firewall.JailbreakResponse{
			Scores: firewall.JailbreakScores{
				MaliciousPrompt: 0.5,
			},
		}

		responseJSON, err := json.Marshal(expectedResponse)
		require.NoError(t, err)
		openAIResponse := map[string]interface{}{
			"output_text": string(responseJSON),
		}

		var receivedUserContent string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var requestBody map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&requestBody) //nolint:errcheck

			if input, ok := requestBody["input"].(string); ok {
				receivedUserContent = input
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(openAIResponse) //nolint:errcheck
		}))
		defer server.Close()

		client := firewall.NewOpenAIFirewallClient(logrus.New())
		client.(*firewall.OpenAIFirewallClient).SetEndpoint(server.URL) //nolint:errcheck

		credentials := firewall.Credentials{
			OpenAICredentials: firewall.OpenAICredentials{
				APIKey: "test-api-key",
			},
		}
		content := firewall.Content{
			Input: []string{"line 1", "line 2", "line 3"},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "line 1\nline 2\nline 3", receivedUserContent)
	})
}
