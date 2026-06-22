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

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	bedrockClient "github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrockTypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	smithy "github.com/aws/smithy-go"
)

type client struct {
	clientPool    *sync.Map
	buildMu       sync.Mutex
	bedrockClient bedrockClient.Client
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
	model := c.resolveModel(reqBody, cfg.DefaultModel)
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
	})
	if err != nil {
		if backendErr := newBedrockBackendError(err); backendErr != nil {
			return nil, backendErr
		}
		return nil, fmt.Errorf("failed to invoke model: %w", err)
	}

	return resp.Body, nil
}

func (c *client) CompletionsStream(
	ctx context.Context,
	cfg *providers.Config,
	reqBody []byte,
) (iter.Seq2[[]byte, error], error) {
	model := c.resolveModel(reqBody, cfg.DefaultModel)
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

// resolveModel extracts the model from the request body. Falls back to
// defaultModel when the body doesn't contain a model field. Strips a leading
// region prefix (e.g. "eu.") so the value passed to InvokeModel is the standard
// Bedrock model ID.
func (c *client) resolveModel(reqBody []byte, defaultModel string) string {
	if modelID, err := extractBedrockModelID(reqBody); err == nil && modelID != "" {
		return modelID
	}
	m := defaultModel
	if extracted, err := adapter.ExtractModel(reqBody); err == nil && extracted != "" {
		m = extracted
	}
	return bedrockModelID(m)
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

// bedrockModelID returns the model ID to pass to InvokeModel. Removes a leading
// "eu." region prefix when present so the API receives the standard Bedrock
// identifier. The "us." prefix is left as-is since it is part of some Bedrock
// model IDs.
func bedrockModelID(model string) string {
	if strings.HasPrefix(model, "eu.") {
		return strings.TrimPrefix(model, "eu.")
	}
	return model
}
