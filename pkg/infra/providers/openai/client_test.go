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

func TestAsk_MissingAPIKey(t *testing.T) {
	client := openai.NewOpenaiClient()

	config := &providers.Config{
		Model: "gpt-4",
		Credentials: providers.Credentials{
			ApiKey: "",
		},
	}

	resp, err := client.Ask(context.Background(), config, "test prompt")

	assert.Error(t, err, "Ask should return an error when API key is missing")
	assert.Nil(t, resp, "Ask should return nil response when API key is missing")
	assert.Contains(t, err.Error(), "API key is required", "Error message should indicate missing API key")
}

func TestAsk_MissingModel(t *testing.T) {
	client := openai.NewOpenaiClient()

	config := &providers.Config{
		Model: "",
		Credentials: providers.Credentials{
			ApiKey: "test-api-key",
		},
	}

	resp, err := client.Ask(context.Background(), config, "test prompt")
	assert.Error(t, err, "Ask should return an error when model is missing")
	assert.Nil(t, resp, "Ask should return nil response when model is missing")
	assert.Contains(t, err.Error(), "model is required", "Error message should indicate missing model")
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

	// This will fail due to invalid API key, but we can test the API selection logic
	_, err := client.Completions(context.Background(), config, reqBody)

	// We expect an error due to invalid API key, but not due to API selection
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "openAI completions request failed")
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

	// This will fail due to invalid API key, but we can test the API selection logic
	_, err := client.Completions(context.Background(), config, reqBody)

	// We expect an error due to invalid API key, but not due to API selection
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "openAI responses request failed")
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

	// This will fail due to invalid API key, but we can test the API selection logic
	_, err := client.Completions(context.Background(), config, reqBody)

	// We expect an error due to invalid API key, but not due to API selection
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "openAI completions request failed")
}

func TestCompletionsAPI_InvalidAPI(t *testing.T) {
	client := openai.NewOpenaiClient()

	config := &providers.Config{
		Credentials: providers.Credentials{
			ApiKey: "test-api-key",
		},
		Options: map[string]interface{}{
			"api": "invalid-api",
		},
	}

	reqBody := []byte(`{
		"model": "gpt-3.5-turbo",
		"messages": [
			{"role": "user", "content": "Hello"}
		]
	}`)

	_, err := client.Completions(context.Background(), config, reqBody)

	// We expect an error due to unsupported API type
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported API type: invalid-api")
}

func TestCompletionsAPI_ResponsesAPI_WithSystemAndAssistant(t *testing.T) {
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
		"model": "gpt-4.1",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Hello, how are you?"},
			{"role": "assistant", "content": "I'm doing well, thank you!"},
			{"role": "user", "content": "Tell me a joke."}
		]
	}`)

	// This will fail due to invalid API key, but we can test the transformation logic
	_, err := client.Completions(context.Background(), config, reqBody)

	// We expect an error due to invalid API key, but not due to transformation
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "openAI responses request failed")
}
