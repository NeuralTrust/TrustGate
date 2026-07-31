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

// Package controlplane queries the Amazon Bedrock control plane to discover
// which model identifiers a set of credentials can invoke serverless.
//
// "Serverless" here means billed per request with no resource to deploy: base
// models offering ON_DEMAND throughput, plus the system-defined cross-region
// inference profiles (us./eu./global./…) that front them. Everything else
// InvokeModel accepts in its modelId — Bedrock Marketplace endpoints,
// Provisioned Throughput, custom and imported models — requires an ARN of a
// resource the customer created, so it can never be served from a shared
// catalog and is deliberately left out.
//
// Both calls are plain SigV4-signed GETs rather than the service/bedrock SDK
// module, matching how pkg/infra/cache signs its ElastiCache requests.
package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	// signingService is the SigV4 service name of the Bedrock control plane.
	signingService = "bedrock"
	// emptyPayloadHash is sha256(""), the payload hash of a body-less GET.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// endpointEnvVar mirrors the AWS SDK's per-service endpoint override, so a
	// VPC endpoint (or a test double) can be pointed at without code changes.
	endpointEnvVar = "AWS_ENDPOINT_URL_BEDROCK"

	requestTimeout   = 15 * time.Second
	maxResponseBytes = 4 << 20

	foundationModelsPath  = "/foundation-models"
	inferenceProfilesPath = "/inference-profiles"

	// inferenceTypeOnDemand marks a base model that can be invoked by its plain
	// model ID; inferenceTypeProfile marks one reachable only through an
	// inference profile, whose IDs are collected separately.
	inferenceTypeOnDemand = "ON_DEMAND"
	inferenceTypeProfile  = "INFERENCE_PROFILE"

	// profileTypeSystemDefined selects the cross-region profiles AWS predefines;
	// APPLICATION profiles are customer-created and account-specific.
	profileTypeSystemDefined = "SYSTEM_DEFINED"
	profileStatusActive      = "ACTIVE"
	profilePageSize          = "1000"
	// maxProfilePages bounds pagination so a repeating nextToken cannot spin.
	maxProfilePages = 10

	assumeRoleSessionName = "TrustGateBedrockCatalog"
)

// ErrRegionRequired is returned when credentials carry no region: the control
// plane endpoint is regional, so there is nothing to query without one.
var ErrRegionRequired = errors.New("bedrock controlplane: aws region is required")

// Credentials carries a registry's AWS auth material. It is duplicated here
// rather than imported from pkg/infra/providers so app services can depend on
// this package without pulling in the provider invocation layer.
type Credentials struct {
	Region       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	UseRole      bool
	RoleARN      string
}

// CacheKey identifies the credential set a result belongs to. It deliberately
// omits the secret key: the access key (or assumed role) plus region already
// identify the account whose catalog was read.
func (c Credentials) CacheKey() string {
	return fmt.Sprintf("%s|%s|%v|%s", c.Region, c.AccessKey, c.UseRole, c.RoleARN)
}

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=bedrock_controlplane_client_mock.go --case=underscore --with-expecter
type Client interface {
	// ListServerlessModelIDs returns the set of modelId values these credentials
	// can pass to InvokeModel without deploying anything: on-demand base models
	// and system-defined inference profiles.
	ListServerlessModelIDs(ctx context.Context, creds Credentials) (map[string]struct{}, error)
}

var _ Client = (*client)(nil)

type client struct {
	httpClient *http.Client
	signer     *v4.Signer
	loadConfig func(ctx context.Context, creds Credentials) (aws.Config, error)
	// endpoint overrides the resolved regional host when non-empty.
	endpoint string
}

func NewClient() Client {
	return &client{
		httpClient: &http.Client{Timeout: requestTimeout},
		signer:     v4.NewSigner(),
		loadConfig: loadAwsConfig,
		endpoint:   strings.TrimRight(os.Getenv(endpointEnvVar), "/"),
	}
}

func (c *client) ListServerlessModelIDs(ctx context.Context, creds Credentials) (map[string]struct{}, error) {
	if creds.Region == "" {
		return nil, ErrRegionRequired
	}
	cfg, err := c.loadConfig(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("bedrock controlplane: load aws config: %w", err)
	}
	awsCreds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("bedrock controlplane: retrieve aws credentials: %w", err)
	}

	ids := make(map[string]struct{})
	if err := c.collectFoundationModels(ctx, awsCreds, creds.Region, ids); err != nil {
		return nil, err
	}
	if err := c.collectInferenceProfiles(ctx, awsCreds, creds.Region, ids); err != nil {
		return nil, err
	}
	return ids, nil
}

type foundationModelsResponse struct {
	ModelSummaries []struct {
		ModelID                 string   `json:"modelId"`
		InferenceTypesSupported []string `json:"inferenceTypesSupported"`
	} `json:"modelSummaries"`
}

// collectFoundationModels adds every base model that can be billed per request.
// Models flagged INFERENCE_PROFILE only are counted too: their plain ID is not
// invocable, but keeping them lets the catalog show the model, and the matching
// profile ID arrives from collectInferenceProfiles.
func (c *client) collectFoundationModels(
	ctx context.Context,
	awsCreds aws.Credentials,
	region string,
	out map[string]struct{},
) error {
	var payload foundationModelsResponse
	if err := c.get(ctx, awsCreds, region, foundationModelsPath, nil, &payload); err != nil {
		return err
	}
	for _, summary := range payload.ModelSummaries {
		if summary.ModelID == "" {
			continue
		}
		for _, inferenceType := range summary.InferenceTypesSupported {
			if inferenceType == inferenceTypeOnDemand || inferenceType == inferenceTypeProfile {
				out[summary.ModelID] = struct{}{}
				break
			}
		}
	}
	return nil
}

type inferenceProfilesResponse struct {
	Summaries []struct {
		ID     string `json:"inferenceProfileId"`
		Status string `json:"status"`
		Type   string `json:"type"`
	} `json:"inferenceProfileSummaries"`
	NextToken string `json:"nextToken"`
}

func (c *client) collectInferenceProfiles(
	ctx context.Context,
	awsCreds aws.Credentials,
	region string,
	out map[string]struct{},
) error {
	nextToken := ""
	for page := 0; page < maxProfilePages; page++ {
		query := url.Values{}
		// The wire parameter is "type" even though the API models it as
		// typeEquals.
		query.Set("type", profileTypeSystemDefined)
		query.Set("maxResults", profilePageSize)
		if nextToken != "" {
			query.Set("nextToken", nextToken)
		}

		var payload inferenceProfilesResponse
		if err := c.get(ctx, awsCreds, region, inferenceProfilesPath, query, &payload); err != nil {
			return err
		}
		for _, summary := range payload.Summaries {
			if summary.ID == "" || summary.Status != profileStatusActive {
				continue
			}
			out[summary.ID] = struct{}{}
		}
		if payload.NextToken == "" || payload.NextToken == nextToken {
			return nil
		}
		nextToken = payload.NextToken
	}
	return nil
}

func (c *client) get(
	ctx context.Context,
	awsCreds aws.Credentials,
	region, path string,
	query url.Values,
	out any,
) error {
	endpoint := c.baseURL(region) + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("bedrock controlplane: build request %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/json")
	if err := c.signer.SignHTTP(
		ctx, awsCreds, req, emptyPayloadHash, signingService, region, time.Now(),
	); err != nil {
		return fmt.Errorf("bedrock controlplane: sign %s: %w", path, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("bedrock controlplane: call %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("bedrock controlplane: read %s: %w", path, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("bedrock controlplane: %s returned %d: %s",
			path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("bedrock controlplane: decode %s: %w", path, err)
	}
	return nil
}

// baseURL resolves the regional control plane host. Only the commercial and
// China partitions differ in suffix; GovCloud regions follow the commercial
// form. Anything else (FIPS, VPC endpoints) is covered by the env override.
func (c *client) baseURL(region string) string {
	if c.endpoint != "" {
		return c.endpoint
	}
	if strings.HasPrefix(region, "cn-") {
		return fmt.Sprintf("https://%s.%s.amazonaws.com.cn", signingService, region)
	}
	return fmt.Sprintf("https://%s.%s.amazonaws.com", signingService, region)
}

func loadAwsConfig(ctx context.Context, creds Credentials) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(creds.Region)}
	if creds.AccessKey != "" && creds.SecretKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			awscredentials.NewStaticCredentialsProvider(creds.AccessKey, creds.SecretKey, creds.SessionToken),
		))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}
	if creds.UseRole && creds.RoleARN != "" {
		provider := stscreds.NewAssumeRoleProvider(
			sts.NewFromConfig(cfg), creds.RoleARN,
			func(o *stscreds.AssumeRoleOptions) { o.RoleSessionName = assumeRoleSessionName },
		)
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return cfg, nil
}
