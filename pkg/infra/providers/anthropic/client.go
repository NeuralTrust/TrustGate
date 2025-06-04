package anthropic

import (
	"context"
	"fmt"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

type client struct {
	clientPool *sync.Map
}

func NewAnthropicClient() providers.Client {
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

	anthropicClient := c.getOrCreateClient(config.Credentials.ApiKey)

	var messages []anthropic.MessageParam

	if len(config.Instructions) > 0 {
		messages = append(messages, anthropic.NewUserMessage(
			anthropic.NewTextBlock(providers.FormatInstructions(config.Instructions)),
		))
	}

	if prompt != "" {
		messages = append(messages, anthropic.NewUserMessage(
			anthropic.NewTextBlock(prompt),
		))
	}

	model := anthropic.ModelClaude3OpusLatest
	if config.Model != "" {
		model = anthropic.Model(config.Model)
	}

	params := anthropic.MessageNewParams{
		Model:     model,
		Messages:  messages,
		MaxTokens: int64(config.MaxTokens),
	}

	if config.SystemPrompt != "" {
		params.System = []anthropic.TextBlockParam{
			{
				Text: config.SystemPrompt,
				Type: "text",
			},
		}
	}

	if config.Temperature > 0 {
		params.Temperature = anthropic.Float(config.Temperature)
	}

	message, err := anthropicClient.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}

	if len(message.Content) == 0 {
		return nil, fmt.Errorf("no completions returned")
	}

	var responseText string
	for _, content := range message.Content {
		if content.Type == "text" {
			responseText = content.Text
			break
		}
	}

	if responseText == "" {
		return nil, fmt.Errorf("no text content returned")
	}

	return &providers.CompletionResponse{
		ID:       message.ID,
		Model:    string(model),
		Response: responseText,
		Usage: providers.Usage{
			PromptTokens:     int(message.Usage.InputTokens),
			CompletionTokens: int(message.Usage.OutputTokens),
			TotalTokens:      int(message.Usage.InputTokens + message.Usage.OutputTokens),
		},
	}, nil
}

func (c *client) getOrCreateClient(apiKey string) anthropic.Client {
	if clientVal, ok := c.clientPool.Load(apiKey); ok {
		return clientVal.(anthropic.Client)
	}
	newClient := anthropic.NewClient(
		option.WithAPIKey(apiKey),
	)
	c.clientPool.Store(apiKey, newClient)
	return newClient
}
