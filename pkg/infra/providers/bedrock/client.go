package bedrock

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	bedrockClient "github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

const (
	ModelPrefixAnthropicClaude   = "anthropic.claude"
	ModelPrefixAnthropicClaudeV3 = "anthropic.claude-3"
	ModelPrefixAmazonTitan       = "amazon.titan"
	ModelPrefixDeepseek          = "deepseek"
	ModelPrefixMistral           = "mistral"
	ModelPrefixMetaLlama         = "meta.llama"
)

type CompletionRequest struct {
	Model            string                   `json:"model"`
	Messages         []map[string]interface{} `json:"messages"`
	MaxTokens        int                      `json:"max_tokens"`
	Stream           bool                     `json:"stream"`
	System           string                   `json:"system"`
	AnthropicVersion string                   `json:"anthropic_version"`
}

type Request struct {
	Prompt            string  `json:"prompt,omitempty"`
	MaxTokensToSample int     `json:"max_tokens_to_sample,omitempty"`
	Temperature       float64 `json:"temperature,omitempty"`

	// Anthropic Claude specific fields
	AnthropicVersion string                   `json:"anthropic_version,omitempty"`
	Messages         []map[string]interface{} `json:"messages,omitempty"`
	System           string                   `json:"system,omitempty"`

	// Amazon Titan specific fields
	InputText            string                 `json:"inputText,omitempty"`
	TextGenerationConfig map[string]interface{} `json:"textGenerationConfig,omitempty"`

	// Mistral specific fields
	MaxTokens int     `json:"max_tokens,omitempty"`
	TopP      float64 `json:"top_p,omitempty"`

	// Deepseek specific fields
	FrequencyPenalty float64 `json:"frequency_penalty,omitempty"`
	PresencePenalty  float64 `json:"presence_penalty,omitempty"`
}

type Response struct {
	// Claude specific fields
	Completion string `json:"completion,omitempty"`

	// Claude 3 specific fields
	Content []map[string]interface{} `json:"content,omitempty"`

	// Titan specific fields
	Results    []map[string]interface{} `json:"results,omitempty"`
	OutputText string                   `json:"outputText,omitempty"`

	// Mistral specific fields
	Generation string `json:"generation,omitempty"`

	// Llama specific fields
	Generation2 string `json:"llama_generation,omitempty"` // Different field name to avoid conflict with Mistral

	Response string `json:"response,omitempty"`
	Text     string `json:"text,omitempty"`
	Output   string `json:"output,omitempty"`
}

type client struct {
	clientPool    *sync.Map
	bedrockClient bedrockClient.Client
}

func NewBedrockClient() providers.Client {
	bedrockClientInstance := bedrockClient.NewClient()
	return &client{
		clientPool:    &sync.Map{},
		bedrockClient: bedrockClientInstance,
	}
}

func (c *client) Completions(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	if config.DefaultModel == "" {
		return nil, fmt.Errorf("model is required")
	}
	if config.Model == "" {
		config.Model = config.DefaultModel
	}

	bedrockCl, err := c.getOrCreateClient(ctx, config.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	mappedBody, err := c.prepareRequestFromBody(config, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}

	resp, err := bedrockCl.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(config.DefaultModel),
		ContentType: aws.String("application/json"),
		Body:        mappedBody,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to invoke model: %w", err)
	}

	return resp.Body, nil
}

func (c *client) CompletionsStream(
	ctx context.Context,
	config *providers.Config,
	reqBody []byte,
	streamChan chan []byte,
	breakChan chan struct{},
) error {
	if config.DefaultModel == "" {
		return fmt.Errorf("model is required")
	}
	if config.Model == "" {
		config.Model = config.DefaultModel
	}

	bedrockCl, err := c.getOrCreateClient(ctx, config.Credentials)
	if err != nil {
		return fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	mappedBody, err := c.prepareRequestFromBody(config, reqBody)
	if err != nil {
		return fmt.Errorf("failed to prepare request: %w", err)
	}

	resp, err := bedrockCl.InvokeModelWithResponseStream(ctx, &bedrockruntime.InvokeModelWithResponseStreamInput{
		ModelId:     aws.String(config.Model),
		ContentType: aws.String("application/json"),
		Body:        mappedBody,
	})
	if err != nil {
		streamChan <- []byte(fmt.Sprintf(`{"error": "invoke error: %s"}`, err.Error()))
		return err
	}
	close(breakChan)

	for event := range resp.GetStream().Reader.Events() {
		switch v := event.(type) {
		case *types.ResponseStreamMemberChunk:
			var chunk map[string]interface{}
			if err := json.Unmarshal(v.Value.Bytes, &chunk); err != nil {
				streamChan <- []byte(fmt.Sprintf(`{"error": "unmarshal error: %s"}`, err.Error()))
				continue
			}

			// Process the chunk based on the provider type
			if typeContent, ok := chunk["type"].(string); ok {
				// CLAUDE
				c.processClaudeStreamResponse(chunk, typeContent, streamChan)
			} else if output, ok := chunk["outputText"].(string); ok {
				// TITAN
				c.processTitanStreamResponse(output, streamChan)
			} else if output, ok := chunk["generation"].(string); ok {
				// LLAMA
				c.processLlamaStreamResponse(output, streamChan)
			} else if choicesRaw, ok := chunk["choices"].([]interface{}); ok {
				// MISTRAL
				c.processMistralStreamResponse(choicesRaw, streamChan)
			}

		default:
			streamChan <- []byte(`{"error": "unknown stream event"}`)
		}
	}

	if err := resp.GetStream().Reader.Err(); err != nil {
		streamChan <- []byte(fmt.Sprintf(`{"error": "stream error: %s"}`, err.Error()))
	}

	return nil
}

func (c *client) Ask(
	ctx context.Context,
	config *providers.Config,
	prompt string,
) (*providers.CompletionResponse, error) {

	if config.Model == "" {
		return nil, fmt.Errorf("model is required")
	}

	bedrockCl, err := c.getOrCreateClient(ctx, config.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	request, err := c.prepareRequest(config, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := bedrockCl.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(config.Model),
		ContentType: aws.String("application/json"),
		Body:        body,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to invoke model: %w", err)
	}

	responseText, err := c.parseResponse(config.Model, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	var id string
	if requestID := ctx.Value("requestID"); requestID != nil {
		id = fmt.Sprintf("bedrock-%v", requestID)
	} else {
		id = fmt.Sprintf("bedrock-%d", time.Now().UnixNano())
	}

	completionResp := &providers.CompletionResponse{
		ID:       id,
		Model:    config.Model,
		Response: responseText,
		Usage:    providers.Usage{},
	}

	return completionResp, nil
}

func (c *client) prepareRequest(config *providers.Config, prompt string) (*Request, error) {
	request := &Request{}

	if config.MaxTokens > 0 {
		request.MaxTokensToSample = config.MaxTokens
	}
	if config.Temperature > 0 {
		request.Temperature = config.Temperature
	}

	switch {
	case isClaudeModel(config.Model):
		return c.prepareClaudeRequest(config, prompt, request)
	case isTitanModel(config.Model):
		return c.prepareTitanRequest(config, prompt, request)
	case isMistralModel(config.Model):
		return c.prepareMistralRequest(config, prompt, request)
	case isLlamaModel(config.Model):
		return c.prepareLlamaRequest(config, prompt, request)
	case isDeepseekModel(config.Model):
		return c.prepareDeepseekRequest(config, prompt, request)
	default:
		return c.prepareDefaultRequest(config, prompt, request)
	}
}

func (c *client) prepareClaudeRequest(config *providers.Config, prompt string, request *Request) (*Request, error) {
	if config.SystemPrompt != "" {
		request.System = config.SystemPrompt
	}
	if isClaudeV3Model(config.Model) {
		var messages []map[string]interface{}
		if len(config.Instructions) > 0 {
			messages = append(messages, map[string]interface{}{
				"role":    "user",
				"content": providers.FormatInstructions(config.Instructions),
			})
		}

		if prompt != "" {
			messages = append(messages, map[string]interface{}{
				"role":    "user",
				"content": prompt,
			})
		}

		request.Messages = messages
	} else {
		var fullPrompt string
		if len(config.Instructions) > 0 {
			fullPrompt += providers.FormatInstructions(config.Instructions) + "\n\n"
		}
		if prompt != "" {
			fullPrompt += prompt
		}
		request.Prompt = fullPrompt
	}
	return request, nil
}

func (c *client) prepareTitanRequest(config *providers.Config, prompt string, request *Request) (*Request, error) {
	var fullPrompt string
	if config.SystemPrompt != "" {
		fullPrompt += config.SystemPrompt + "\n\n"
	}
	if len(config.Instructions) > 0 {
		fullPrompt += providers.FormatInstructions(config.Instructions) + "\n\n"
	}
	if prompt != "" {
		fullPrompt += prompt
	}
	request.InputText = fullPrompt
	request.TextGenerationConfig = map[string]interface{}{
		"maxTokenCount": config.MaxTokens,
		"temperature":   config.Temperature,
	}
	return request, nil
}

func (c *client) prepareMistralRequest(config *providers.Config, prompt string, request *Request) (*Request, error) {
	var fullPrompt string
	if config.SystemPrompt != "" {
		fullPrompt += config.SystemPrompt + "\n\n"
	}
	if len(config.Instructions) > 0 {
		fullPrompt += providers.FormatInstructions(config.Instructions) + "\n\n"
	}
	if prompt != "" {
		fullPrompt += prompt
	}
	request.Prompt = fullPrompt
	request.MaxTokens = config.MaxTokens
	request.Temperature = config.Temperature
	request.TopP = 0.9
	return request, nil
}

func (c *client) prepareLlamaRequest(config *providers.Config, prompt string, request *Request) (*Request, error) {
	var fullPrompt string
	if config.SystemPrompt != "" {
		fullPrompt += config.SystemPrompt + "\n\n"
	}
	if len(config.Instructions) > 0 {
		fullPrompt += providers.FormatInstructions(config.Instructions) + "\n\n"
	}
	if prompt != "" {
		fullPrompt += prompt
	}
	request.Prompt = fullPrompt
	request.MaxTokens = config.MaxTokens
	request.Temperature = config.Temperature
	request.TopP = 0.9
	return request, nil
}

func (c *client) prepareDeepseekRequest(config *providers.Config, prompt string, request *Request) (*Request, error) {
	var fullPrompt string
	if config.SystemPrompt != "" {
		fullPrompt += config.SystemPrompt + "\n\n"
	}
	if len(config.Instructions) > 0 {
		fullPrompt += providers.FormatInstructions(config.Instructions) + "\n\n"
	}
	if prompt != "" {
		fullPrompt += prompt
	}
	request.Prompt = fullPrompt
	request.MaxTokens = config.MaxTokens
	request.Temperature = config.Temperature
	request.TopP = 0.9
	request.FrequencyPenalty = 0.0
	request.PresencePenalty = 0.0
	return request, nil
}

func (c *client) prepareDefaultRequest(config *providers.Config, prompt string, request *Request) (*Request, error) {
	var fullPrompt string
	if config.SystemPrompt != "" {
		fullPrompt += config.SystemPrompt + "\n\n"
	}
	if len(config.Instructions) > 0 {
		fullPrompt += providers.FormatInstructions(config.Instructions) + "\n\n"
	}
	if prompt != "" {
		fullPrompt += prompt
	}
	request.Prompt = fullPrompt
	return request, nil
}

func (c *client) parseResponse(model string, responseBody []byte) (string, error) {
	var responseText string
	var err error

	switch {
	case isClaudeModel(model):
		responseText, err = c.parseClaudeResponse(model, responseBody)
	case isTitanModel(model):
		responseText, err = c.parseTitanResponse(responseBody)
	case isMistralModel(model):
		responseText, err = c.parseMistralResponse(responseBody)
	case isLlamaModel(model):
		responseText, err = c.parseLlamaResponse(responseBody)
	case isDeepseekModel(model):
		responseText, err = c.parseDeepseekResponse(responseBody)
	default:
		responseText, err = c.parseDefaultResponse(responseBody)
	}

	if err != nil {
		return "", err
	}

	if responseText == "" {
		return "", fmt.Errorf("no text content returned")
	}

	return responseText, nil
}

func (c *client) parseClaudeResponse(model string, responseBody []byte) (string, error) {
	if isClaudeV3Model(model) {
		var response struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}

		if err := json.Unmarshal(responseBody, &response); err != nil {
			return "", fmt.Errorf("failed to unmarshal Claude 3 response: %w", err)
		}

		for _, content := range response.Content {
			if content.Type == "text" {
				return content.Text, nil
			}
		}
		return "", nil
	} else {
		var response struct {
			Completion string `json:"completion"`
		}
		if err := json.Unmarshal(responseBody, &response); err != nil {
			return "", fmt.Errorf("failed to unmarshal Claude response: %w", err)
		}
		return response.Completion, nil
	}
}

func (c *client) parseTitanResponse(responseBody []byte) (string, error) {
	var response struct {
		OutputText string `json:"outputText"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal Titan response: %w", err)
	}
	return response.OutputText, nil
}

func (c *client) parseMistralResponse(responseBody []byte) (string, error) {
	var response struct {
		Generation string `json:"generation"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal Mistral response: %w", err)
	}
	return response.Generation, nil
}

func (c *client) parseLlamaResponse(responseBody []byte) (string, error) {
	var response struct {
		Generation string `json:"llama_generation"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		var fallbackResponse struct {
			Generation string `json:"generation"`
		}
		if err2 := json.Unmarshal(responseBody, &fallbackResponse); err2 != nil {
			return "", fmt.Errorf("failed to unmarshal Llama response: %w", err2)
		}
		return fallbackResponse.Generation, nil
	}
	return response.Generation, nil
}

func (c *client) parseDeepseekResponse(responseBody []byte) (string, error) {
	var response struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		var altResponse struct {
			Output string `json:"output"`
		}
		if err2 := json.Unmarshal(responseBody, &altResponse); err2 != nil {
			return "", fmt.Errorf("failed to unmarshal Deepseek response: %w", err2)
		}
		return altResponse.Output, nil
	}
	return response.Response, nil
}

func (c *client) parseDefaultResponse(responseBody []byte) (string, error) {
	var response Response
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if response.Completion != "" {
		return response.Completion, nil
	} else if response.OutputText != "" {
		return response.OutputText, nil
	} else if response.Generation != "" {
		return response.Generation, nil
	} else if response.Generation2 != "" {
		return response.Generation2, nil
	} else if response.Response != "" {
		return response.Response, nil
	} else if response.Text != "" {
		return response.Text, nil
	} else if response.Output != "" {
		return response.Output, nil
	} else if len(response.Content) > 0 {
		for _, content := range response.Content {
			if text, ok := content["text"].(string); ok {
				return text, nil
			}
		}
	} else if len(response.Results) > 0 {
		for _, result := range response.Results {
			if text, ok := result["outputText"].(string); ok {
				return text, nil
			}
		}
	}

	return "", nil
}

func (c *client) getOrCreateClient(ctx context.Context, credentials providers.Credentials) (*bedrockruntime.Client, error) {
	clientKey := buildClientKey(credentials)
	if clientVal, ok := c.clientPool.Load(clientKey); ok {
		client, ok := clientVal.(*bedrockruntime.Client)
		if !ok {
			return nil, fmt.Errorf("invalid client type in pool")
		}
		return client, nil
	}
	if c.bedrockClient == nil {
		cfg, err := buildAwsConfig(ctx, credentials)
		if err != nil {
			return nil, err
		}
		bedrockRuntimeClient := bedrockruntime.NewFromConfig(cfg)
		c.clientPool.Store(clientKey, bedrockRuntimeClient)
		return bedrockRuntimeClient, nil
	}

	var accessKey, secretKey, region, sessionToken string
	var useRole bool
	var roleARN string

	if credentials.AwsBedrock != nil {
		accessKey = credentials.AwsBedrock.AccessKey
		secretKey = credentials.AwsBedrock.SecretKey
		sessionToken = credentials.AwsBedrock.SessionToken
		region = credentials.AwsBedrock.Region
		useRole = credentials.AwsBedrock.UseRole
		roleARN = credentials.AwsBedrock.RoleARN
	} else {
		return nil, fmt.Errorf("aws credentials are required")
	}

	bedrockClientInstance, err := c.bedrockClient.BuildClient(
		ctx,
		accessKey,
		secretKey,
		sessionToken,
		region,
		useRole,
		roleARN,
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build Bedrock client: %w", err)
	}
	runtimeClient := bedrockClientInstance.GetRuntimeClient()
	if runtimeClient == nil {
		return nil, fmt.Errorf("failed to get runtime client")
	}
	c.clientPool.Store(clientKey, runtimeClient)

	return runtimeClient, nil
}

func buildClientKey(credentials providers.Credentials) string {
	if credentials.AwsBedrock == nil {
		return credentials.ApiKey
	}
	return fmt.Sprintf("%s:%s:%s:%v:%s",
		credentials.ApiKey,
		credentials.AwsBedrock.AccessKey,
		credentials.AwsBedrock.Region,
		credentials.AwsBedrock.UseRole,
		credentials.AwsBedrock.RoleARN,
	)
}

func buildAwsConfig(ctx context.Context, credentials providers.Credentials) (aws.Config, error) {
	const defaultRegion = "us-east-1"

	if credentials.AwsBedrock == nil {
		return loadAWSConfig(ctx, credentials.ApiKey, credentials.ApiKey, "", defaultRegion)
	}

	region := credentials.AwsBedrock.Region
	if region == "" {
		region = defaultRegion
	}

	accessKey := credentials.AwsBedrock.AccessKey
	secretKey := credentials.AwsBedrock.SecretKey

	if credentials.AwsBedrock.UseRole && credentials.AwsBedrock.RoleARN != "" {
		creds, err := assumeRole(ctx, accessKey, secretKey, credentials.AwsBedrock.RoleARN, region)
		if err != nil {
			return aws.Config{}, err
		}
		return loadAWSConfig(ctx, *creds.AccessKeyId, *creds.SecretAccessKey, *creds.SessionToken, region)
	}

	return loadAWSConfig(ctx, accessKey, secretKey, "", region)
}

func loadAWSConfig(ctx context.Context, accessKey, secretKey, sessionToken, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     accessKey,
					SecretAccessKey: secretKey,
					SessionToken:    sessionToken,
				}, nil
			},
		)),
		config.WithRegion(region),
	)
}

func assumeRole(ctx context.Context, accessKey, secretKey, roleARN, region string, sessionName ...string) (*stsTypes.Credentials, error) {
	baseCfg, err := loadAWSConfig(ctx, accessKey, secretKey, "", region)
	if err != nil {
		return nil, fmt.Errorf("unable to load base AWS config: %w", err)
	}
	stsClient := sts.NewFromConfig(baseCfg)

	roleName := "BedrockClientSession"
	if len(sessionName) > 0 && sessionName[0] != "" {
		roleName = sessionName[0]
	}

	output, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to assume role: %w", err)
	}
	return output.Credentials, nil
}

func isClaudeModel(model string) bool {
	return strings.Contains(model, ModelPrefixAnthropicClaude)
}

func isClaudeV3Model(model string) bool {
	return strings.Contains(model, ModelPrefixAnthropicClaudeV3)
}

func isTitanModel(model string) bool {
	return strings.Contains(model, ModelPrefixAmazonTitan)
}

func isDeepseekModel(model string) bool {
	return strings.Contains(model, ModelPrefixDeepseek)
}

func isMistralModel(model string) bool {
	return strings.Contains(model, ModelPrefixMistral)
}

func isLlamaModel(model string) bool {
	return strings.Contains(model, ModelPrefixMetaLlama)
}

func (c *client) prepareRequestFromBody(config *providers.Config, reqBody []byte) ([]byte, error) {
	var req CompletionRequest
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request body: %w", err)
	}

	// Extract user message from messages array
	var userMessage string
	for _, msg := range req.Messages {
		if role, ok := msg["role"].(string); ok && role == "user" {
			if content, ok := msg["content"].(string); ok {
				userMessage = content
				break
			}
		}
	}

	if userMessage == "" {
		return nil, fmt.Errorf("user message not found in request")
	}

	// Create a new config with the values from the request
	newConfig := *config
	if req.MaxTokens > 0 {
		newConfig.MaxTokens = req.MaxTokens
	}
	if req.System != "" {
		newConfig.SystemPrompt = req.System
	}

	// Prepare the request based on the model
	request := &Request{}

	if newConfig.Temperature > 0 {
		request.Temperature = newConfig.Temperature
	}
	if req.AnthropicVersion != "" {
		request.AnthropicVersion = req.AnthropicVersion
	}

	var err error
	switch {
	case isClaudeModel(config.Model):
		request, err = c.prepareClaudeRequestFromMessages(config, req.Messages, request)
	case isTitanModel(config.Model):
		request, err = c.prepareTitanRequestFromMessages(config, req.Messages, request)
	case isMistralModel(config.Model):
		request, err = c.prepareMistralRequestFromMessages(config, req.Messages, request)
	case isLlamaModel(config.Model):
		request, err = c.prepareLlamaRequestFromMessages(config, req.Messages, request)
	case isDeepseekModel(config.Model):
		request, err = c.prepareDeepseekRequestFromMessages(config, req.Messages, request)
	default:
		request, err = c.prepareDefaultRequestFromMessages(config, req.Messages, request)
	}

	if err != nil {
		return nil, err
	}

	return json.Marshal(request)
}

func (c *client) prepareClaudeRequestFromMessages(config *providers.Config, messages []map[string]interface{}, request *Request) (*Request, error) {
	if config.SystemPrompt != "" {
		request.System = config.SystemPrompt
	}
	if config.MaxTokens > 0 {
		request.MaxTokens = config.MaxTokens
	}

	if isClaudeV3Model(config.Model) {
		request.Messages = messages
		if request.AnthropicVersion == "" {
			request.AnthropicVersion = "bedrock-2023-05-31"
		}
	} else {
		// For Claude 2, we need to format the messages as a prompt
		var prompt string
		for _, msg := range messages {
			if role, ok := msg["role"].(string); ok {
				if content, ok := msg["content"].(string); ok {
					if role == "user" {
						prompt += "Human: " + content + "\n\n"
					} else if role == "assistant" {
						prompt += "Assistant: " + content + "\n\n"
					}
				}
			}
		}
		prompt += "Assistant: "
		request.Prompt = prompt
	}

	if request.MaxTokens == 0 {
		request.MaxTokens = 1024
	}

	return request, nil
}

func (c *client) prepareTitanRequestFromMessages(config *providers.Config, messages []map[string]interface{}, request *Request) (*Request, error) {
	var inputText string

	if config.SystemPrompt != "" {
		inputText += config.SystemPrompt + "\n\n"
	}

	for _, msg := range messages {
		if role, ok := msg["role"].(string); ok {
			if content, ok := msg["content"].(string); ok {
				if role == "user" {
					inputText += "User: " + content + " "
				} else if role == "assistant" {
					inputText += "Assistant: " + content + " "
				}
			}
		}
	}
	req := &Request{}
	req.InputText = inputText
	req.TextGenerationConfig = map[string]interface{}{}
	if config.MaxTokens > 0 {
		req.TextGenerationConfig["max_tokens"] = config.MaxTokens
	}
	if config.Temperature > 0 {
		req.TextGenerationConfig["temperature"] = config.Temperature
	}

	return req, nil
}

func (c *client) prepareMistralRequestFromMessages(config *providers.Config, messages []map[string]interface{}, request *Request) (*Request, error) {
	var prompt string

	if config.SystemPrompt != "" {
		prompt += config.SystemPrompt + "\n\n"
	}

	for _, msg := range messages {
		if role, ok := msg["role"].(string); ok {
			if content, ok := msg["content"].(string); ok {
				if role == "user" {
					prompt += "User: " + content + "\n"
				} else if role == "assistant" {
					prompt += "Assistant: " + content + "\n"
				}
			}
		}
	}

	request.Prompt = prompt
	request.MaxTokens = config.MaxTokens
	request.Temperature = config.Temperature
	request.TopP = 0.9

	return request, nil
}

func (c *client) prepareLlamaRequestFromMessages(config *providers.Config, messages []map[string]interface{}, request *Request) (*Request, error) {
	var prompt string

	if config.SystemPrompt != "" {
		prompt += config.SystemPrompt + "\n\n"
	}

	for _, msg := range messages {
		if role, ok := msg["role"].(string); ok {
			if content, ok := msg["content"].(string); ok {
				if role == "user" {
					prompt += "User: " + content + "\n"
				} else if role == "assistant" {
					prompt += "Assistant: " + content + "\n"
				}
			}
		}
	}

	request.Prompt = prompt
	request.MaxTokens = config.MaxTokens
	request.Temperature = config.Temperature
	request.TopP = 0.9

	return request, nil
}

func (c *client) prepareDeepseekRequestFromMessages(config *providers.Config, messages []map[string]interface{}, request *Request) (*Request, error) {
	var prompt string

	if config.SystemPrompt != "" {
		prompt += config.SystemPrompt + "\n\n"
	}

	for _, msg := range messages {
		if role, ok := msg["role"].(string); ok {
			if content, ok := msg["content"].(string); ok {
				if role == "user" {
					prompt += "User: " + content + "\n"
				} else if role == "assistant" {
					prompt += "Assistant: " + content + "\n"
				}
			}
		}
	}

	request.Prompt = prompt
	request.MaxTokens = config.MaxTokens
	request.Temperature = config.Temperature
	request.TopP = 0.9
	request.FrequencyPenalty = 0.0
	request.PresencePenalty = 0.0

	return request, nil
}

func (c *client) prepareDefaultRequestFromMessages(config *providers.Config, messages []map[string]interface{}, request *Request) (*Request, error) {
	var prompt string

	if config.SystemPrompt != "" {
		prompt += config.SystemPrompt + "\n\n"
	}

	for _, msg := range messages {
		if role, ok := msg["role"].(string); ok {
			if content, ok := msg["content"].(string); ok {
				if role == "user" {
					prompt += "User: " + content + "\n"
				} else if role == "assistant" {
					prompt += "Assistant: " + content + "\n"
				}
			}
		}
	}

	request.Prompt = prompt

	return request, nil
}

// processClaudeStreamResponse processes Claude's streaming response format
func (c *client) processClaudeStreamResponse(chunk map[string]interface{}, typeContent string, streamChan chan []byte) {
	if typeContent == "content_block_delta" {
		delta, ok := chunk["delta"].(map[string]interface{})
		if !ok {
			streamChan <- []byte(`{"error": "delta is not a map"}`)
			return
		}

		text, ok := delta["text"].(string)
		if !ok {
			return
		}

		msg := map[string]string{"content": text}
		if b, err := json.Marshal(msg); err == nil {
			streamChan <- b
		}
	}
}

// processTitanStreamResponse processes Titan's streaming response format
func (c *client) processTitanStreamResponse(output string, streamChan chan []byte) {
	msg := map[string]string{"content": output}
	if b, err := json.Marshal(msg); err == nil {
		streamChan <- b
	}
}

// processLlamaStreamResponse processes Llama's streaming response format
func (c *client) processLlamaStreamResponse(output string, streamChan chan []byte) {
	msg := map[string]string{"content": output}
	if b, err := json.Marshal(msg); err == nil {
		streamChan <- b
	}
}

// processMistralStreamResponse processes Mistral's streaming response format
func (c *client) processMistralStreamResponse(choicesRaw []interface{}, streamChan chan []byte) {
	for _, choiceRaw := range choicesRaw {
		choice, ok := choiceRaw.(map[string]interface{})
		if !ok {
			continue
		}

		message, ok := choice["message"].(map[string]interface{})
		if !ok {
			continue
		}

		content, ok := message["content"].(string)
		if !ok {
			continue
		}

		msg := map[string]string{"content": content}
		if b, err := json.Marshal(msg); err == nil {
			streamChan <- b
		}
	}
}
