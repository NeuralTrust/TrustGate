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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	bedrockClient "github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrockTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const credentialsExpiryWindow = 5 * time.Minute

var (
	_ providers.Client           = (*client)(nil)
	_ providers.EmbeddingsClient = (*client)(nil)
)

// Bedrock reports the token counts of a buffered answer in these headers, for
// every family, whether or not the body repeats them.
const (
	inputCountHeader  = "X-Amzn-Bedrock-Input-Token-Count"
	outputCountHeader = "X-Amzn-Bedrock-Output-Token-Count"
)

type invokeModelFn func(ctx context.Context, model string, body []byte) ([]byte, error)

type client struct {
	clientPool    *sync.Map
	buildMu       sync.Mutex
	bedrockClient bedrockClient.Client
	invoke        invokeModelFn
}

func NewBedrockClient() providers.Client {
	bedrockClientInstance := bedrockClient.NewClient()
	return &client{
		clientPool:    &sync.Map{},
		bedrockClient: bedrockClientInstance,
	}
}

// Completions sends reqBody raw to InvokeModel (non-streaming).
func (c *client) Completions(
	ctx context.Context,
	cfg *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	model := c.resolveModel(reqBody, cfg)
	if model == "" {
		return nil, fmt.Errorf("model is required")
	}

	reqBody = stripBedrockFields(reqBody)

	bedrockCl, err := c.getOrCreateClient(ctx, cfg.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	resp, err := bedrockCl.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(model),
		ContentType: aws.String("application/json"),
		Body:        reqBody,
	}, withRawResponse)
	if err != nil {
		if backendErr := newBedrockBackendError(err); backendErr != nil {
			return nil, backendErr
		}
		return nil, fmt.Errorf("failed to invoke model: %w", err)
	}

	return withHeaderTokenCounts(resp.Body, rawResponseHeaders(resp.ResultMetadata)), nil
}

func (c *client) Embeddings(
	ctx context.Context,
	cfg *providers.Config,
	reqBody []byte,
) ([]byte, error) {
	model := c.resolveModel(reqBody, cfg)
	if model == "" {
		return nil, fmt.Errorf("model is required")
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

// withRawResponse keeps the HTTP response reachable from the output metadata,
// which is the only way to read the token-count headers: they are not modelled
// in InvokeModelOutput. The SDK copies the options per call, so appending here
// does not touch the pooled client.
func withRawResponse(o *bedrockruntime.Options) {
	o.APIOptions = append(o.APIOptions, awsmiddleware.AddRawResponseToMetadata)
}

func rawResponseHeaders(md middleware.Metadata) http.Header {
	raw, ok := awsmiddleware.GetRawResponse(md).(*smithyhttp.Response)
	if !ok || raw == nil || raw.Response == nil {
		return nil
	}
	return raw.Header
}

// withHeaderTokenCounts splices the token counts Bedrock reports in headers into
// the response body, under the same key the streaming path already carries them
// in. Some families report usage nowhere else — a legacy Mistral answer is a
// bare {"outputs":[…]} — so without this a buffered call looks free to every
// plugin that charges for tokens.
//
// The counts go in first on purpose: a body that already carries real metrics
// repeats the key, and the last occurrence is the one Go decodes, so the
// upstream's own figures still win.
func withHeaderTokenCounts(body []byte, headers http.Header) []byte {
	if headers == nil {
		return body
	}
	in := headerCount(headers, inputCountHeader)
	out := headerCount(headers, outputCountHeader)
	if in == 0 && out == 0 {
		return body
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return body
	}
	rest := bytes.TrimLeft(trimmed[1:], " \t\r\n")
	if len(rest) == 0 {
		return body
	}

	metrics := fmt.Sprintf(
		`"amazon-bedrock-invocationMetrics":{"inputTokenCount":%d,"outputTokenCount":%d}`,
		in, out,
	)
	merged := make([]byte, 0, len(metrics)+len(trimmed)+1)
	merged = append(merged, '{')
	merged = append(merged, metrics...)
	if rest[0] != '}' {
		merged = append(merged, ',')
	}
	return append(merged, rest...)
}

func headerCount(headers http.Header, name string) int {
	value := headers.Get(name)
	if value == "" {
		return 0
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 0 {
		return 0
	}
	return count
}

func (c *client) CompletionsStream(
	ctx context.Context,
	cfg *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	model := c.resolveModel(reqBody, cfg)
	if model == "" {
		return nil, fmt.Errorf("model is required")
	}

	reqBody = stripBedrockFields(reqBody)

	bedrockCl, err := c.getOrCreateClient(ctx, cfg.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bedrock client: %w", err)
	}

	resp, err := bedrockCl.InvokeModelWithResponseStream(ctx, &bedrockruntime.InvokeModelWithResponseStreamInput{
		ModelId:     aws.String(model),
		ContentType: aws.String("application/json"),
		Body:        reqBody,
	})
	if err != nil {
		if backendErr := newBedrockBackendError(err); backendErr != nil {
			return nil, backendErr
		}
		return nil, fmt.Errorf("failed to invoke model: %w", err)
	}

	stream := resp.GetStream()
	return func(yield func([]byte, error) bool) {
		defer func() { _ = stream.Close() }()
		for event := range stream.Events() {
			if ctxErr := ctx.Err(); ctxErr != nil {
				yield(nil, ctxErr)
				return
			}
			chunk, ok := event.(*bedrockTypes.ResponseStreamMemberChunk)
			if !ok || len(chunk.Value.Bytes) == 0 {
				continue
			}
			line := make([]byte, 0, len(chunk.Value.Bytes)+6)
			line = append(line, []byte("data: ")...)
			line = append(line, chunk.Value.Bytes...)
			if !yield(line, nil) {
				return
			}
			if !yield([]byte{}, nil) {
				return
			}
		}
		if streamErr := stream.Err(); streamErr != nil {
			yield(nil, fmt.Errorf("bedrock stream error: %w", streamErr))
		}
	}, nil
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

// stripBedrockFields removes keys from the JSON body that the Bedrock
// InvokeModel API does not accept. The model is passed as ModelId in the API
// call.
func stripBedrockFields(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	delete(raw, "model")
	delete(raw, "modelId")
	delete(raw, "stream")
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

// Cross-format adaptation strips the model from the body (Bedrock resolves it
// from the InvokeModel path), so it falls back to cfg.
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

// The model identifier is passed through to InvokeModel untouched. A geography
// prefix such as "eu." or "us." names a cross-region inference profile, which is
// the only way to invoke many newer models: rewriting it to the bare model ID
// makes AWS answer "Invocation of model ID … with on-demand throughput isn't
// supported. Retry your request with the ID or ARN of an inference profile".
