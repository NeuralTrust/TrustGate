package gemini

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"google.golang.org/genai"
)

type client struct {
	genaiClient *genai.Client
}

func NewGeminiClient(apiKey string) (providers.Client, error) {
	ctx := context.Background()
	genaiClient, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, err
	}

	return &client{
		genaiClient: genaiClient,
	}, nil
}

func (c *client) Ask(
	ctx context.Context,
	config *providers.Config,
	prompt string,
) (*providers.CompletionResponse, error) {
	if config.Credentials.HeaderValue == "" {
		return nil, fmt.Errorf("API key is required")
	}

	if config.Model == "" {
		config.Model = "gemini-pro"
	}

	var parts []*genai.Part
	if config.SystemPrompt != "" {
		parts = append(parts, &genai.Part{
			Text: config.SystemPrompt,
		})
	}
	if len(config.Instructions) > 0 {
		parts = append(parts, &genai.Part{
			Text: providers.FormatInstructions(config.Instructions),
		})
	}

	result, err := c.genaiClient.Models.GenerateContent(
		ctx,
		config.Model,
		genai.Text(prompt),
		&genai.GenerateContentConfig{
			SystemInstruction: &genai.Content{
				Parts: parts,
				Role:  "system",
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}

	responseText := result.Text()
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	var id string
	if requestID := ctx.Value("requestID"); requestID != nil {
		id = fmt.Sprintf("gemini-%v", requestID)
	} else {
		id = fmt.Sprintf("gemini-%d", time.Now().UnixNano())
	}

	completionResp := &providers.CompletionResponse{
		ID:       id,
		Model:    config.Model,
		Response: responseText,
	}

	completionResp.Usage = providers.Usage{
		PromptTokens:     int(result.UsageMetadata.PromptTokenCount),
		CompletionTokens: int(result.UsageMetadata.CandidatesTokenCount),
		TotalTokens:      int(result.UsageMetadata.TotalTokenCount),
	}

	if responseText == "" {
		return nil, fmt.Errorf("no completions returned")
	}

	return completionResp, nil
}
