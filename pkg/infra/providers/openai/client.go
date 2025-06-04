package openai

import (
	"context"
	"fmt"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

type client struct {
	clientPool *sync.Map
}

func NewOpenaiClient() providers.Client {
	return &client{
		clientPool: &sync.Map{},
	}
}

func (c *client) Ask(
	ctx context.Context,
	config *providers.Config,
	prompt string,
) (*providers.CompletionResponse, error) {
	if config.Credentials.ApiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	if config.Model == "" {
		return nil, fmt.Errorf("model is required")
	}

	openaiClient := c.getOrCreateClient(config.Credentials.ApiKey)

	var messages []openai.ChatCompletionMessageParamUnion

	if config.SystemPrompt != "" {
		messages = append(messages, openai.SystemMessage(config.SystemPrompt))
	}

	if len(config.Instructions) > 0 {
		messages = append(messages, openai.UserMessage(providers.FormatInstructions(config.Instructions)))
	}

	if prompt != "" {
		messages = append(messages, openai.UserMessage(prompt))
	}

	params := openai.ChatCompletionNewParams{
		Model:    config.Model,
		Messages: messages,
	}

	if config.MaxTokens > 0 {
		params.MaxTokens = openai.Int(int64(config.MaxTokens))
	}

	if config.Temperature > 0 {
		params.Temperature = openai.Float(config.Temperature)
	}

	resp, err := openaiClient.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("OpenAI request failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no completions returned")
	}

	return &providers.CompletionResponse{
		ID:       resp.ID,
		Model:    resp.Model,
		Response: resp.Choices[0].Message.Content,
		Usage: providers.Usage{
			PromptTokens:     int(resp.Usage.PromptTokens),
			CompletionTokens: int(resp.Usage.CompletionTokens),
			TotalTokens:      int(resp.Usage.TotalTokens),
		},
	}, nil
}

func (c *client) getOrCreateClient(apiKey string) openai.Client {
	if clientVal, ok := c.clientPool.Load(apiKey); ok {
		return clientVal.(openai.Client)
	}
	newClient := openai.NewClient(option.WithAPIKey(apiKey))
	c.clientPool.Store(apiKey, newClient)
	return newClient
}
