package openai_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestNewOpenaiClient(t *testing.T) {
	client := openai.NewOpenaiClient(&fasthttp.Client{})
	assert.NotNil(t, client, "NewOpenaiClient should return a non-nil client")
}

func TestAsk_MissingAPIKey(t *testing.T) {
	client := openai.NewOpenaiClient(&fasthttp.Client{})

	config := &providers.Config{
		Model: "gpt-4",
		Credentials: providers.Credentials{
			HeaderKey:   "Authorization",
			HeaderValue: "",
		},
	}

	resp, err := client.Ask(context.Background(), config, "test prompt")

	assert.Error(t, err, "Ask should return an error when API key is missing")
	assert.Nil(t, resp, "Ask should return nil response when API key is missing")
	assert.Contains(t, err.Error(), "API key is required", "Error message should indicate missing API key")
}

func TestAsk_MissingModel(t *testing.T) {
	client := openai.NewOpenaiClient(&fasthttp.Client{})

	config := &providers.Config{
		Model: "",
		Credentials: providers.Credentials{
			HeaderKey:   "Authorization",
			HeaderValue: "test-api-key",
		},
	}

	resp, err := client.Ask(context.Background(), config, "test prompt")
	assert.Error(t, err, "Ask should return an error when model is missing")
	assert.Nil(t, resp, "Ask should return nil response when model is missing")
	assert.Contains(t, err.Error(), "model is required", "Error message should indicate missing model")
}
