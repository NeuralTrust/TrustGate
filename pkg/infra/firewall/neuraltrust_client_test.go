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
)

func TestNewNeuralTrustFirewallClient(t *testing.T) {
	logger := logrus.New()

	t.Run("With custom HTTP client", func(t *testing.T) {
		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(
			logger,
			firewall.WithHTTPClient(httpClient),
		)

		assert.NotNil(t, client)
		assert.IsType(t, &firewall.NeuralTrustFirewallClient{}, client)
	})

	t.Run("With default HTTP client", func(t *testing.T) {
		client := firewall.NewNeuralTrustFirewallClient(logger)

		assert.NotNil(t, client)
		assert.IsType(t, &firewall.NeuralTrustFirewallClient{}, client)
	})
}

func TestNeuralTrustFirewallClient_DetectJailbreak(t *testing.T) {
	logger := logrus.New()

	t.Run("Success", func(t *testing.T) {
		expectedResponse := []firewall.JailbreakResponse{{
			Scores: firewall.JailbreakScores{
				MaliciousPrompt: 0.8,
			},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/v1/jailbreak", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "test-token", r.Header.Get("Token"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(expectedResponse) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test prompt"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		// Execute
		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedResponse[0].Scores.MaliciousPrompt, result[0].Scores.MaliciousPrompt)
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		// Create test server that returns invalid JSON
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("invalid json")) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test prompt"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to parse response")
	})

	t.Run("Context cancellation", func(t *testing.T) {
		// Create test server with delay
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		// Create context with short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test prompt"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		result, err := client.DetectJailbreak(ctx, content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestNeuralTrustFirewallClient_DetectToxicity(t *testing.T) {
	logger := logrus.New()

	t.Run("Success", func(t *testing.T) {
		// Create test server
		expectedResponse := []firewall.ToxicityResponse{{
			Scores: map[string]float64{
				"toxic_prompt": 0.7,
			},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/v1/toxicity", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "test-token", r.Header.Get("Token"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(expectedResponse) //nolint:errcheck
		}))
		defer server.Close()

		// Create client
		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		// Test data
		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test content"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		// Execute
		result, err := client.DetectToxicity(context.Background(), content, credentials)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedResponse[0].Scores["toxic_prompt"], result[0].Scores["toxic_prompt"])
	})

	t.Run("Success with CategoryScores", func(t *testing.T) {
		// Create test server
		expectedResponse := []firewall.ToxicityResponse{{
			CategoryScores: map[string]float64{
				"toxic_prompt": 0.6,
			},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(expectedResponse) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test content"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, expectedResponse[0].CategoryScores["toxic_prompt"], result[0].CategoryScores["toxic_prompt"])
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		// Create test server that returns invalid JSON
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("invalid json")) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test content"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to parse response")
	})
}

func TestNeuralTrustFirewallClient_RequestPool(t *testing.T) {
	logger := logrus.New()

	t.Run("Request pool reuse", func(t *testing.T) {
		// Create test server
		expectedResponse := []firewall.JailbreakResponse{{
			Scores: firewall.JailbreakScores{
				MaliciousPrompt: 0.5,
			},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(expectedResponse) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test prompt"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		// Execute multiple requests to test pool reuse
		for i := 0; i < 3; i++ {
			result, err := client.DetectJailbreak(context.Background(), content, credentials)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		}
	})
}

func TestNeuralTrustFirewallClient_BufferPool(t *testing.T) {
	logger := logrus.New()

	t.Run("Buffer pool reuse", func(t *testing.T) {
		// Create test server
		expectedResponse := []firewall.ToxicityResponse{{
			Scores: map[string]float64{
				"toxic_prompt": 0.3,
			},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(expectedResponse) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test content"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		// Execute multiple requests to test buffer pool reuse
		for i := 0; i < 3; i++ {
			result, err := client.DetectToxicity(context.Background(), content, credentials)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		}
	})
}

func TestNeuralTrustFirewallClient_ConcurrentRequests(t *testing.T) {
	logger := logrus.New()

	t.Run("Concurrent jailbreak requests", func(t *testing.T) {
		// Create test server
		expectedResponse := []firewall.JailbreakResponse{{
			Scores: firewall.JailbreakScores{
				MaliciousPrompt: 0.4,
			},
		}}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(expectedResponse) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}
		requestBody := []byte(`{"text": "test prompt"}`)
		content := firewall.Content{
			Input: []string{string(requestBody)},
		}

		// Execute concurrent requests
		const numRequests = 10
		results := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				_, err := client.DetectJailbreak(context.Background(), content, credentials)
				results <- err
			}()
		}

		// Collect results
		for i := 0; i < numRequests; i++ {
			err := <-results
			assert.NoError(t, err)
		}
	})
}

func TestNeuralTrustFirewallClient_EmptyRequestBody(t *testing.T) {
	logger := logrus.New()

	t.Run("Empty jailbreak request body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]firewall.JailbreakResponse{{}}) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}

		content := firewall.Content{
			Input: []string{""},
		}
		result, err := client.DetectJailbreak(context.Background(), content, credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("Empty toxicity request body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]firewall.ToxicityResponse{{}}) //nolint:errcheck
		}))
		defer server.Close()

		httpClient := &http.Client{Timeout: 5 * time.Second}
		client := firewall.NewNeuralTrustFirewallClient(logger, firewall.WithHTTPClient(httpClient))

		credentials := firewall.Credentials{
			NeuralTrustCredentials: firewall.NeuralTrustCredentials{
				BaseURL: server.URL,
				Token:   "test-token",
			},
		}

		content := firewall.Content{
			Input: []string{""},
		}
		result, err := client.DetectToxicity(context.Background(), content, credentials)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}
