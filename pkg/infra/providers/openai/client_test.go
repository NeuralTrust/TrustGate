package openai_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
	"github.com/stretchr/testify/assert"
)

func TestNewOpenaiClient(t *testing.T) {
	client := openai.NewOpenaiClient()
	assert.NotNil(t, client, "NewOpenaiClient should return a non-nil client")
}

func TestCompletions_MissingAPIKey(t *testing.T) {
	client := openai.NewOpenaiClient()
	config := &providers.Config{}
	_, err := client.Completions(context.Background(), config, []byte(`{}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key is required")
}

func TestCompletionsAPI_CompletionsAPI(t *testing.T) {
	client := openai.NewOpenaiClient()

	config := &providers.Config{
		Credentials: providers.Credentials{
			ApiKey: "test-api-key",
		},
		Options: map[string]interface{}{
			"api": "completions",
		},
	}

	reqBody := []byte(`{
		"model": "gpt-3.5-turbo",
		"messages": [
			{"role": "user", "content": "Hello"}
		]
	}`)

	// This will fail due to invalid API key hitting the real endpoint.
	_, err := client.Completions(context.Background(), config, reqBody)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API request failed with status")
}

func TestCompletionsAPI_ResponsesAPI(t *testing.T) {
	client := openai.NewOpenaiClient()

	config := &providers.Config{
		Credentials: providers.Credentials{
			ApiKey: "test-api-key",
		},
		Options: map[string]interface{}{
			"api": "responses",
		},
	}

	reqBody := []byte(`{
		"model": "gpt-3.5-turbo",
		"messages": [
			{"role": "user", "content": "Hello"}
		]
	}`)

	_, err := client.Completions(context.Background(), config, reqBody)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API request failed with status")
}

func TestCompletionsAPI_DefaultAPI(t *testing.T) {
	client := openai.NewOpenaiClient()

	config := &providers.Config{
		Credentials: providers.Credentials{
			ApiKey: "test-api-key",
		},
		// No options specified, should default to completions API
	}

	reqBody := []byte(`{
		"model": "gpt-3.5-turbo",
		"messages": [
			{"role": "user", "content": "Hello"}
		]
	}`)

	_, err := client.Completions(context.Background(), config, reqBody)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API request failed with status")
}
