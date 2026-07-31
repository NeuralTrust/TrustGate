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
// which model identifiers a set of credentials can actually invoke.
//
// Two independent things have to hold, and the control plane reports them
// through different APIs:
//
//   - The model must be serverless — billed per request with no resource to
//     deploy: a base model offering ON_DEMAND throughput, or a system-defined
//     cross-region inference profile (us./eu./global./…) fronting one.
//     Everything else InvokeModel accepts in its modelId (Bedrock Marketplace
//     endpoints, Provisioned Throughput, custom and imported models) needs the
//     ARN of a resource the customer created, so it cannot come from a shared
//     catalog. ListFoundationModels and ListInferenceProfiles answer this.
//   - The account must have been granted access to it. ListFoundationModels
//     returns every model in the region regardless of access, so entitlement is
//     a separate GetFoundationModelAvailability call per model — without it the
//     catalog would keep offering models that fail with AccessDeniedException.
//
// All calls are plain SigV4-signed GETs rather than the service/bedrock SDK
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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/errgroup"
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
	availabilityPath      = "/foundation-model-availability/"

	// entitlementConcurrency bounds the per-model availability calls, which run
	// once per credential set per cache window.
	entitlementConcurrency = 8

	statusAuthorized = "AUTHORIZED"
	statusAvailable  = "AVAILABLE"

	// inferenceTypeOnDemand marks a base model that can be invoked by its plain
	// model ID. A model without it is reachable only through an inference
	// profile, whose IDs are collected separately.
	inferenceTypeOnDemand = "ON_DEMAND"

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

// Availability is the verdict on a set of candidate model IDs.
type Availability struct {
	// ModelIDs are the candidates these credentials can invoke.
	ModelIDs map[string]struct{}
	// EntitlementChecked reports whether model access was actually verified. It
	// is false when the credentials cannot call GetFoundationModelAvailability
	// (it needs bedrock:GetFoundationModelAvailability), in which case ModelIDs
	// is only known to be serverless and may still contain models that fail with
	// AccessDeniedException. Callers use it to tell a trustworthy empty result
	// from an unverifiable one.
	EntitlementChecked bool
}

//go:generate mockery --name=Client --dir=. --output=./mocks --filename=bedrock_controlplane_client_mock.go --case=underscore --with-expecter
type Client interface {
	// ListInvocableModelIDs narrows candidates to the model IDs these credentials
	// can pass to InvokeModel and get a completion back: serverless, in this
	// region, and with model access granted to the account.
	//
	// Candidates are filtered rather than the region's full model list enumerated
	// so the per-model entitlement calls stay proportional to what the caller
	// would actually offer.
	ListInvocableModelIDs(ctx context.Context, creds Credentials, candidates []string) (Availability, error)
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

func (c *client) ListInvocableModelIDs(
	ctx context.Context,
	creds Credentials,
	candidates []string,
) (Availability, error) {
	if creds.Region == "" {
		return Availability{}, ErrRegionRequired
	}
	if len(candidates) == 0 {
		return Availability{ModelIDs: map[string]struct{}{}, EntitlementChecked: true}, nil
	}

	cfg, err := c.loadConfig(ctx, creds)
	if err != nil {
		return Availability{}, fmt.Errorf("bedrock controlplane: load aws config: %w", err)
	}
	awsCreds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return Availability{}, fmt.Errorf("bedrock controlplane: retrieve aws credentials: %w", err)
	}

	serverless := make(map[string]struct{})
	if err := c.collectFoundationModels(ctx, awsCreds, creds.Region, serverless); err != nil {
		return Availability{}, err
	}
	if err := c.collectInferenceProfiles(ctx, awsCreds, creds.Region, serverless); err != nil {
		return Availability{}, err
	}

	shortlist := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := serverless[candidate]; ok {
			shortlist = append(shortlist, candidate)
		}
	}

	entitled, checked := c.entitlements(ctx, awsCreds, creds.Region, shortlist)
	out := make(map[string]struct{}, len(shortlist))
	for _, id := range shortlist {
		if !checked {
			out[id] = struct{}{}
			continue
		}
		// Entitlement is granted on the underlying base model, so every regional
		// profile of a model shares one verdict.
		if entitled[baseModelID(id)] {
			out[id] = struct{}{}
		}
	}
	return Availability{ModelIDs: out, EntitlementChecked: checked}, nil
}

type availabilityResponse struct {
	// AgreementAvailability reports whether the account holds the model's
	// agreement (its AWS Marketplace subscription). It is the field that goes
	// NOT_AVAILABLE while the other three still read positive, which is what an
	// account that never completed the subscription looks like.
	AgreementAvailability struct {
		Status string `json:"status"`
	} `json:"agreementAvailability"`
	AuthorizationStatus     string `json:"authorizationStatus"`
	EntitlementAvailability string `json:"entitlementAvailability"`
	RegionAvailability      string `json:"regionAvailability"`
}

// invocable reports whether all four availability signals are positive. Any one
// of them being negative makes InvokeModel fail with AccessDeniedException.
func (r availabilityResponse) invocable() bool {
	return r.AgreementAvailability.Status == statusAvailable &&
		r.AuthorizationStatus == statusAuthorized &&
		r.EntitlementAvailability == statusAvailable &&
		r.RegionAvailability == statusAvailable
}

// entitlements resolves model access for the distinct base models behind ids.
// It returns checked=false when no verdict could be obtained at all — a missing
// bedrock:GetFoundationModelAvailability permission must not silently empty the
// caller's catalog — while a single model that errors is simply treated as not
// entitled once at least one other verdict came back.
func (c *client) entitlements(
	ctx context.Context,
	awsCreds aws.Credentials,
	region string,
	ids []string,
) (map[string]bool, bool) {
	bases := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		bases[baseModelID(id)] = struct{}{}
	}
	if len(bases) == 0 {
		return nil, true
	}

	var (
		mu       sync.Mutex
		verdicts = make(map[string]bool, len(bases))
		answered bool
	)
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(entitlementConcurrency)
	for base := range bases {
		base := base
		group.Go(func() error {
			var payload availabilityResponse
			err := c.get(groupCtx, awsCreds, region, availabilityPath+url.PathEscape(base), nil, &payload)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				verdicts[base] = false
				return nil
			}
			answered = true
			verdicts[base] = payload.invocable()
			return nil
		})
	}
	_ = group.Wait()

	if !answered {
		return nil, false
	}
	return verdicts, true
}

// baseModelID strips the geography prefix of a cross-region inference profile
// ("eu.anthropic.claude-…" -> "anthropic.claude-…"), which is the ID model
// access is granted on. Plain model IDs are returned unchanged.
func baseModelID(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) < 3 {
		return id
	}
	if _, ok := profileGeoPrefixes[parts[0]]; !ok {
		return id
	}
	return strings.Join(parts[1:], ".")
}

// profileGeoPrefixes are the geography scopes AWS puts in front of a model ID to
// name its cross-region inference profile.
var profileGeoPrefixes = map[string]struct{}{
	"us": {}, "us-gov": {}, "eu": {}, "apac": {}, "jp": {}, "au": {},
	"ca": {}, "sa": {}, "global": {},
}

type foundationModelsResponse struct {
	ModelSummaries []struct {
		ModelID                 string   `json:"modelId"`
		InferenceTypesSupported []string `json:"inferenceTypesSupported"`
	} `json:"modelSummaries"`
}

// collectFoundationModels adds the base models invocable by their plain ID, i.e.
// those offering ON_DEMAND throughput.
//
// A model whose only inference type is INFERENCE_PROFILE is deliberately left
// out: passing its bare ID to InvokeModel fails with "Invocation of model ID …
// with on-demand throughput isn't supported. Retry your request with the ID or
// ARN of an inference profile". Such a model reaches the catalog through its
// profile IDs, which collectInferenceProfiles adds.
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
		if slices.Contains(summary.InferenceTypesSupported, inferenceTypeOnDemand) {
			out[summary.ModelID] = struct{}{}
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
