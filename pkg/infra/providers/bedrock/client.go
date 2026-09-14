// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bedrock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"strings"
	"sync"
	"time"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
	bedrockClient "github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
)

const credentialsExpiryWindow = 5 * time.Minute

var (
	_ providers.Client           = (*client)(nil)
	_ providers.EmbeddingsClient = (*client)(nil)
)

type invokeModelFn func(ctx context.Context, model string, body []byte) ([]byte, error)

type converseFn func(ctx context.Context, input *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, error)

type client struct {
	clientPool    *sync.Map
	buildMu       sync.Mutex
	bedrockClient bedrockClient.Client
	invoke        invokeModelFn
	converse      converseFn
	systemFold    systemFoldMemo
}

func NewBedrockClient() providers.Client {
	bedrockClientInstance := bedrockClient.NewClient()
	return &client{
		clientPool:    &sync.Map{},
		bedrockClient: bedrockClientInstance,
	}
}

// Completions sends the Converse body in reqBody to the Converse API and
// returns the answer in the same wire JSON.
func (c *client) Completions(
	ctx context.Context,
	cfg *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	model, err := c.requireModel(reqBody, cfg)
	if err != nil {
		return nil, err
	}
	params, err := decodeConverseBody(reqBody)
	if err != nil {
		return nil, err
	}

	out, err := converseWithSystemFallback(&c.systemFold, model, params,
		func(p *converseParams) (*bedrockruntime.ConverseOutput, error) {
			return c.converseModel(ctx, cfg, p.input(model))
		})
	if err != nil {
		if backendErr := newBedrockBackendError(err); backendErr != nil {
			return nil, backendErr
		}
		return nil, fmt.Errorf("failed to converse with model: %w", err)
	}
	return converseResponseJSON(out)
}

func (c *client) converseModel(
	ctx context.Context,
	cfg *providers.Config,
	input *bedrockruntime.ConverseInput,
) (*bedrockruntime.ConverseOutput, error) {
	if c.converse != nil {
		return c.converse(ctx, input)
	}

	bedrockCl, err := c.getOrCreateClient(ctx, cfg.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}
	return bedrockCl.Converse(ctx, input)
}

func (c *client) Embeddings(
	ctx context.Context,
	cfg *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	model, err := c.requireModel(reqBody, cfg)
	if err != nil {
		return nil, err
	}
	if !isTitanEmbedModel(model) {
		return nil, fmt.Errorf("bedrock embeddings support Titan embed models only, got %q", model)
	}

	texts, err := titanEmbedTexts(reqBody)
	if err != nil {
		return nil, err
	}

	var (
		vectors [][]float64
		tokens  int
	)
	for _, text := range texts {
		invokeBody, err := json.Marshal(titanEmbedInvoke{InputText: text})
		if err != nil {
			return nil, err
		}
		raw, err := c.invokeModel(ctx, cfg, model, invokeBody)
		if err != nil {
			return nil, err
		}
		var native titanEmbedNative
		if err := json.Unmarshal(raw, &native); err != nil {
			return nil, fmt.Errorf("decoding titan embed response: %w", err)
		}
		vectors = append(vectors, native.Embedding)
		tokens += native.InputTextTokenCount
	}

	if len(vectors) == 1 {
		return json.Marshal(titanEmbedNative{
			Embedding:           vectors[0],
			InputTextTokenCount: tokens,
		})
	}
	return json.Marshal(titanEmbedMerged{
		Embeddings:          vectors,
		InputTextTokenCount: tokens,
	})
}

type titanEmbedInvoke struct {
	InputText string `json:"inputText"`
}

type titanEmbedNative struct {
	Embedding           []float64 `json:"embedding"`
	InputTextTokenCount int       `json:"inputTextTokenCount"`
}

type titanEmbedMerged struct {
	Embeddings          [][]float64 `json:"embeddings"`
	InputTextTokenCount int         `json:"inputTextTokenCount"`
}

func titanEmbedTexts(body []byte) ([]string, error) {
	var req struct {
		InputText  string   `json:"inputText"`
		InputTexts []string `json:"inputTexts"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("invalid titan embed request: %w", err)
	}
	if len(req.InputTexts) > 0 {
		return req.InputTexts, nil
	}
	if req.InputText != "" {
		return []string{req.InputText}, nil
	}
	return nil, fmt.Errorf("titan embed request requires inputText")
}

func isTitanEmbedModel(model string) bool {
	return strings.Contains(strings.ToLower(model), "titan-embed")
}

func (c *client) invokeModel(
	ctx context.Context,
	cfg *providers.Config,
	model string,
	body []byte,
) ([]byte, error) {
	if c.invoke != nil {
		return c.invoke(ctx, model, body)
	}

	bedrockCl, err := c.getOrCreateClient(ctx, cfg.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	resp, err := bedrockCl.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(model),
		ContentType: aws.String("application/json"),
		Body:        body,
	})
	if err != nil {
		if backendErr := newBedrockBackendError(err); backendErr != nil {
			return nil, backendErr
		}
		return nil, fmt.Errorf("failed to invoke model: %w", err)
	}
	return resp.Body, nil
}

// CompletionsStream sends the Converse body in reqBody to ConverseStream and
// yields every event as an SSE "data:" line in the adapter's wire JSON.
func (c *client) CompletionsStream(
	ctx context.Context,
	cfg *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	model, err := c.requireModel(reqBody, cfg)
	if err != nil {
		return nil, err
	}
	params, err := decodeConverseBody(reqBody)
	if err != nil {
		return nil, err
	}

	bedrockCl, err := c.getOrCreateClient(ctx, cfg.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	resp, err := converseWithSystemFallback(&c.systemFold, model, params,
		func(p *converseParams) (*bedrockruntime.ConverseStreamOutput, error) {
			return bedrockCl.ConverseStream(ctx, p.streamInput(model))
		})
	if err != nil {
		if backendErr := newBedrockBackendError(err); backendErr != nil {
			return nil, backendErr
		}
		return nil, fmt.Errorf("failed to converse with model: %w", err)
	}

	return converseStreamLines(ctx, resp.GetStream()), nil
}

func newBedrockBackendError(err error) *registrydomain.BackendError {
	var statusErr interface {
		HTTPStatusCode() int
	}
	if !errors.As(err, &statusErr) {
		return nil
	}

	statusCode := statusErr.HTTPStatusCode()
	if !registrydomain.IsHTTPError(statusCode) {
		return nil
	}

	body, marshalErr := json.Marshal(bedrockErrorPayload(err))
	if marshalErr != nil {
		body = []byte(http.StatusText(statusCode))
	}
	return registrydomain.NewBackendError(statusCode, body)
}

func bedrockErrorPayload(err error) map[string]string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return map[string]string{
			"error":   apiErr.ErrorCode(),
			"message": apiErr.ErrorMessage(),
		}
	}
	return map[string]string{"message": err.Error()}
}

// loadClient returns the cached runtime client for key, or false when absent or
// stored under an unexpected type (which triggers a rebuild).
func (c *client) loadClient(key string) (*bedrockruntime.Client, bool) {
	v, ok := c.clientPool.Load(key)
	if !ok {
		return nil, false
	}
	cl, ok := v.(*bedrockruntime.Client)
	return cl, ok
}

func (c *client) getOrCreateClient(ctx context.Context, credentials providers.Credentials) (*bedrockruntime.Client, error) {
	clientKey := buildClientKey(credentials)
	if cl, ok := c.loadClient(clientKey); ok {
		return cl, nil
	}

	// Serialize the check-then-build so concurrent first requests for the same
	// credentials do not each construct (and orphan) a duplicate client.
	c.buildMu.Lock()
	defer c.buildMu.Unlock()
	if cl, ok := c.loadClient(clientKey); ok {
		return cl, nil
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

	if credentials.AwsBedrock == nil {
		return nil, fmt.Errorf("aws credentials are required")
	}

	bedrockClientInstance, err := c.bedrockClient.BuildClient(
		ctx,
		credentials.AwsBedrock.AccessKey,
		credentials.AwsBedrock.SecretKey,
		credentials.AwsBedrock.SessionToken,
		credentials.AwsBedrock.Region,
		credentials.AwsBedrock.UseRole,
		credentials.AwsBedrock.RoleARN,
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
	sessionToken := credentials.AwsBedrock.SessionToken

	awsCfg, err := loadAWSConfig(ctx, accessKey, secretKey, sessionToken, region)
	if err != nil {
		return aws.Config{}, err
	}

	if credentials.AwsBedrock.UseRole && credentials.AwsBedrock.RoleARN != "" {
		stsClient := sts.NewFromConfig(awsCfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, credentials.AwsBedrock.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "BedrockClientSession"
		})
		awsCfg.Credentials = aws.NewCredentialsCache(provider, func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = credentialsExpiryWindow
		})
	}

	return awsCfg, nil
}

func loadAWSConfig(ctx context.Context, accessKey, secretKey, sessionToken, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if accessKey != "" && secretKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			awscredentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken),
		))
	}
	return config.LoadDefaultConfig(ctx, opts...)
}

func (c *client) requireModel(reqBody []byte, cfg *providers.Config) (string, error) {
	model := c.resolveModel(reqBody, cfg)
	if model == "" {
		return "", fmt.Errorf("model is required")
	}
	if err := modelmatch.RequireConcrete("model", model); err != nil {
		return "", err
	}
	return model, nil
}

func (c *client) resolveModel(reqBody []byte, cfg *providers.Config) string {
	if modelID, err := extractBedrockModelID(reqBody); err == nil && modelID != "" {
		return modelID
	}
	if extracted, err := adapter.ExtractModel(reqBody); err == nil && extracted != "" {
		return extracted
	}
	if cfg.Model != "" {
		return cfg.Model
	}
	return cfg.DefaultModel
}

func extractBedrockModelID(body []byte) (string, error) {
	var probe struct {
		ModelID string `json:"modelId"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", err
	}
	return probe.ModelID, nil
}

// The model identifier is passed through to Bedrock untouched. A geography
// prefix such as "eu." or "us." names a cross-region inference profile, which is
// the only way to invoke many newer models: rewriting it to the bare model ID
// makes AWS answer "Invocation of model ID … with on-demand throughput isn't
// supported. Retry your request with the ID or ARN of an inference profile".
