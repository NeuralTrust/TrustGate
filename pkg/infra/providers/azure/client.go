package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

type client struct {
	clientPool *sync.Map
}

func NewAzureClient() providers.Client {
	return &client{
		clientPool: &sync.Map{},
	}
}

// Ask sends a request to the Azure OpenAI API and returns the response
// It supports both API key and Azure AD token authentication
// For API key authentication, set config.Credentials.ApiKey
// For Azure AD token authentication, set config.Credentials.Azure.UseIdentity to true
// Note: Azure AD token authentication is not currently implemented and will return an error
//
// Parameters:
//   - ctx: The context for the request
//   - config: The configuration for the request, including credentials, model, and parameters
//   - prompt: The user's prompt to send to the API
//
// Returns:
//   - *providers.CompletionResponse: The response from the API
//   - error: An error if the request failed
func (c *client) Ask(
	ctx context.Context,
	config *providers.Config,
	prompt string,
) (*providers.CompletionResponse, error) {
	if config.Credentials.Azure == nil {
		return nil, fmt.Errorf("azure configuration is required")
	}

	if config.Credentials.Azure.Endpoint == "" {
		return nil, fmt.Errorf("azure endpoint is required")
	}

	if config.Model == "" {
		return nil, fmt.Errorf("model (deployment ID) is required")
	}

	var token string
	var err error

	if config.Credentials.Azure.UseIdentity {
		token, err = getAzureADToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get Azure AD token: %w", err)
		}
	} else {
		if config.Credentials.ApiKey == "" {
			return nil, fmt.Errorf("API key is required when not using Azure identity")
		}
		token = config.Credentials.ApiKey
	}

	var messages []map[string]string

	if config.SystemPrompt != "" {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": config.SystemPrompt,
		})
	}

	if len(config.Instructions) > 0 {
		messages = append(messages, map[string]string{
			"role":    "user",
			"content": providers.FormatInstructions(config.Instructions),
		})
	}

	if prompt != "" {
		messages = append(messages, map[string]string{
			"role":    "user",
			"content": prompt,
		})
	}
	apiVersion := "2024-02-15-preview"
	if config.Credentials.Azure.ApiVersion != "" {
		apiVersion = config.Credentials.Azure.ApiVersion
	}

	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
		config.Credentials.Azure.Endpoint,
		config.Model,
		apiVersion)

	reqBody := map[string]interface{}{
		"messages": messages,
	}

	if config.Temperature > 0 {
		reqBody["temperature"] = config.Temperature
	}

	if config.MaxTokens > 0 {
		reqBody["max_tokens"] = config.MaxTokens
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Set authorization header based on authentication method
	if config.Credentials.Azure.UseIdentity {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("api-key", token)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyErr, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("non-200 status: %d, error reading response body: %w", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("non-200 status: %d\n%s", resp.StatusCode, string(bodyErr))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the response
	var response map[string]interface{}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract the completion text
	choices, ok := response["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return nil, fmt.Errorf("no completions returned")
	}

	choice, ok := choices[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid completion format")
	}

	message, ok := choice["message"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid message format")
	}

	content, ok := message["content"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid content format")
	}

	// Extract usage information
	usage := providers.Usage{}
	if usageData, ok := response["usage"].(map[string]interface{}); ok {
		if promptTokens, ok := usageData["prompt_tokens"].(float64); ok {
			usage.PromptTokens = int(promptTokens)
		}
		if completionTokens, ok := usageData["completion_tokens"].(float64); ok {
			usage.CompletionTokens = int(completionTokens)
		}
		if totalTokens, ok := usageData["total_tokens"].(float64); ok {
			usage.TotalTokens = int(totalTokens)
		}
	}

	// Generate a unique ID
	var id string
	if requestID := ctx.Value("requestID"); requestID != nil {
		id = fmt.Sprintf("azure-%v", requestID)
	} else {
		id = fmt.Sprintf("azure-%d", time.Now().UnixNano())
	}

	return &providers.CompletionResponse{
		ID:       id,
		Model:    config.Model,
		Response: content,
		Usage:    usage,
	}, nil
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	streamChan chan []byte,
	reqBody []byte,
) error {
	return nil
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	return nil, nil
}

func getAzureADToken(ctx context.Context) (string, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create credential: %w", err)
	}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://cognitiveservices.azure.com/.default"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	return token.Token, nil
}
