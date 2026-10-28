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
//     deploy: a base model offering ON_DEMAND throughput, or a global
//     cross-region inference profile fronting one. Everything else InvokeModel
//     accepts in its modelId (Bedrock Marketplace endpoints, Provisioned
//     Throughput, custom and imported models) needs the ARN of a resource the
//     customer created, so it cannot come from a shared catalog.
//     ListFoundationModels and ListInferenceProfiles answer this.
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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/sync/errgroup"
)

const (
	provisionedModelsPath = "/provisioned-model-throughput/"

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
	// globalProfileGeography names the geography-agnostic inference profile, the
	// only kind the catalog offers. See collectInferenceProfiles.
	globalProfileGeography = "global"
	globalProfilePrefix    = globalProfileGeography + "."
	profilePageSize        = "1000"
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

// cacheKeySalt keys the secret digest in CacheKey. It is random per process, so a
// digest that leaks (a heap dump, a stray log line) cannot be brute-forced
// offline against guessed secrets. The caches CacheKey feeds live in process
// memory only, so nothing needs the digest to be stable across restarts or pods.
var cacheKeySalt = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("controlplane: read random cache key salt: " + err.Error())
	}
	return b
}()

// CacheKey identifies the credential set a result belongs to. The secret key and
// session token enter only as a truncated HMAC-SHA256 under cacheKeySalt, never
// raw: two parties who know the same access key ID but not the same secret must
// not share a cache entry, or one could poison (or read) the other's. The key is
// safe to hold in memory maps, but it is still derived from a secret and must
// not be logged.
func (c Credentials) CacheKey() string {
	mac := hmac.New(sha256.New, cacheKeySalt)
	_, _ = mac.Write([]byte(c.SecretKey + "\x00" + c.SessionToken))
	return fmt.Sprintf("%s|%s|%v|%s|%s", c.Region, c.AccessKey, c.UseRole, c.RoleARN, hex.EncodeToString(mac.Sum(nil)[:8]))
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

	// ResolveModelARN returns the model ARN behind an application inference
	// profile or a Provisioned Throughput ARN, with the credentials' own
	// permissions: bedrock:GetInferenceProfile or
	// bedrock:GetProvisionedModelThroughput. The region of the ARN is queried,
	// which is where the resource lives.
	ResolveModelARN(ctx context.Context, creds Credentials, arn string) (string, error)

	// CheckCatalogAccess probes the three control plane permissions catalog
	// narrowing needs (ListFoundationModels, ListInferenceProfiles and
	// GetFoundationModelAvailability) with one cheap call each, and returns the
	// IAM actions the credentials are denied, in a stable order. Credentials that
	// hold only the runtime permissions (InvokeModel) get all three back. An error
	// is returned only when the probe itself could not run (no credentials, AWS
	// unreachable), never for a denied action.
	CheckCatalogAccess(ctx context.Context, creds Credentials) ([]string, error)
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

// IsGeographyScopedProfile reports whether id names an inference profile bound to
// a single geography ("us.", "eu.", "jp.", "au."…), which is invocable only from
// source regions inside that geography. Plain model IDs and the geography-
// agnostic "global." profile are not scoped and return false.
func IsGeographyScopedProfile(id string) bool {
	parts := strings.Split(id, ".")
	if len(parts) < 3 || parts[0] == globalProfileGeography {
		return false
	}
	_, ok := profileGeoPrefixes[parts[0]]
	return ok
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
		ModelLifecycle          struct {
			Status string `json:"status"`
		} `json:"modelLifecycle"`
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

// collectInferenceProfiles adds the geography-agnostic ("global.") profiles.
//
// Profiles scoped to one geography (us., eu., jp., au.) are skipped even though
// AWS lists them: they are only invocable from source regions inside their own
// geography, so a catalog entry for one is valid for some registries and broken
// for others. A global profile routes from any supported source region, which
// means one entry works whatever region a registry is configured with. Base
// models invocable by their plain ID are unaffected — they come from
// collectFoundationModels.
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
			if !strings.HasPrefix(summary.ID, globalProfilePrefix) {
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
	endpoint, err := c.requestURL(region, path, query)
	if err != nil {
		return err
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
		return &APIError{
			Path:      path,
			Status:    resp.StatusCode,
			Body:      strings.TrimSpace(string(body)),
			ErrorType: errorType(resp.Header.Get("x-amzn-ErrorType"), body),
		}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("bedrock controlplane: decode %s: %w", path, err)
	}
	return nil
}

// singleSegment reports a resource that is one path segment of plain characters
// once decoded: it is written into the path of a signed request, so an empty, dot or
// dot-dot resource, a slash or any character that is not part of an identifier is
// refused here whatever the caller already checked.
func singleSegment(resource string) bool {
	decoded, err := url.PathUnescape(resource)
	if err != nil || decoded == "" || decoded == "." || decoded == ".." {
		return false
	}
	for i := range len(decoded) {
		c := decoded[i]
		plain := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == ':'
		if !plain {
			return false
		}
	}
	return true
}

// ValidRegion reports a well-formed AWS region name. A region is written into a
// host name that signed requests are sent to, so nothing else may pass.
func ValidRegion(region string) bool { return provider.ValidAWSRegion(region) }

// requestURL builds the URL of a control plane call. The region must be a region
// name, the host is parsed back out of the URL and must be an AWS host (unless the
// operator set the endpoint override, which is trusted), and the path and query
// are set on a url.URL, never concatenated: a signed request must not be
// redirectable to another host by anything that reaches here.
func (c *client) requestURL(region, path string, query url.Values) (string, error) {
	if !ValidRegion(region) {
		return "", ErrRegionRequired
	}
	u, err := url.Parse(c.baseURL(region))
	if err != nil {
		return "", fmt.Errorf("bedrock controlplane: build endpoint: %w", err)
	}
	if c.endpoint == "" && !awsHost(u.Hostname()) {
		return "", fmt.Errorf("bedrock controlplane: %w", ErrUnsupportedHost)
	}
	unescaped, err := url.PathUnescape(path)
	if err != nil {
		return "", fmt.Errorf("bedrock controlplane: path %q: %w", path, err)
	}
	u.Path, u.RawPath = unescaped, path
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func awsHost(host string) bool {
	return strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")
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

// ErrUnsupportedARN is returned for an ARN the control plane cannot resolve to a
// model: neither an application inference profile nor provisioned throughput.
var ErrUnsupportedARN = errors.New("bedrock controlplane: arn is not an application inference profile or provisioned model")

// ErrARNRegionMismatch is returned for an ARN of a region other than the
// registry's: it is not resolved, the model stays unpriced.
var ErrARNRegionMismatch = errors.New("bedrock controlplane: arn belongs to another region than the registry")

// ErrUnsupportedHost is returned when the endpoint a request would go to is not an
// AWS host.
var ErrUnsupportedHost = errors.New("endpoint is not an AWS host")

type inferenceProfileResponse struct {
	Models []struct {
		ModelARN string `json:"modelArn"`
	} `json:"models"`
}

type provisionedModelResponse struct {
	ModelARN           string `json:"modelArn"`
	FoundationModelARN string `json:"foundationModelArn"`
}

func (c *client) ResolveModelARN(ctx context.Context, creds Credentials, arn string) (string, error) {
	parsed, ok := bedrocknative.SplitBedrockARN(arn)
	if !ok {
		return "", ErrUnsupportedARN
	}
	kind, resource := parsed.Kind, parsed.Resource
	if !singleSegment(resource) {
		return "", ErrUnsupportedARN
	}
	// The control plane is always asked in the registry's region: the ARN is the
	// caller's, and its region never picks a host. An ARN of another region is
	// not this registry's to resolve.
	region := creds.Region
	if region == "" {
		return "", ErrRegionRequired
	}
	if !ValidRegion(region) {
		return "", ErrRegionRequired
	}
	if parsed.Region != region {
		return "", ErrARNRegionMismatch
	}
	if !provider.ValidAWSAccount(parsed.Account) {
		return "", ErrUnsupportedARN
	}
	cfg, err := c.loadConfig(ctx, creds)
	if err != nil {
		return "", fmt.Errorf("bedrock controlplane: load aws config: %w", err)
	}
	awsCreds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", fmt.Errorf("bedrock controlplane: retrieve aws credentials: %w", err)
	}
	switch kind {
	case bedrocknative.KindApplicationProfile:
		var payload inferenceProfileResponse
		if err := c.get(ctx, awsCreds, region, inferenceProfilesPath+"/"+url.PathEscape(resource), nil, &payload); err != nil {
			return "", err
		}
		for _, m := range payload.Models {
			if m.ModelARN != "" {
				return m.ModelARN, nil
			}
		}
	case bedrocknative.KindProvisionedModel:
		var payload provisionedModelResponse
		if err := c.get(ctx, awsCreds, region, provisionedModelsPath+url.PathEscape(resource), nil, &payload); err != nil {
			return "", err
		}
		if payload.FoundationModelARN != "" {
			return payload.FoundationModelARN, nil
		}
		if payload.ModelARN != "" {
			return payload.ModelARN, nil
		}
	default:
		return "", ErrUnsupportedARN
	}
	return "", fmt.Errorf("bedrock controlplane: %s names no model", arn)
}

// APIError is a non-2xx answer of the control plane.
type APIError struct {
	Path   string
	Status int
	Body   string
	// ErrorType is the AWS error name ("AccessDeniedException",
	// "UnrecognizedClientException"...), read from the x-amzn-ErrorType header or
	// the body's __type; empty when AWS did not say.
	ErrorType string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("bedrock controlplane: %s returned %d: %s", e.Path, e.Status, e.Body)
}

// errorType extracts the AWS error name. The header looks like
// "AccessDeniedException:http://internal.amazon.com/coral/..." and the body's
// __type may carry a namespace prefix ("com.amazon...#AccessDeniedException").
func errorType(header string, body []byte) string {
	name := header
	if name == "" {
		var payload struct {
			Type string `json:"__type"`
		}
		if json.Unmarshal(body, &payload) == nil {
			name = payload.Type
		}
	}
	if k := strings.Index(name, ":"); k >= 0 {
		name = name[:k]
	}
	if k := strings.LastIndex(name, "#"); k >= 0 {
		name = name[k+1:]
	}
	return name
}

var notAuthorizedAction = regexp.MustCompile(`not authorized to perform: (bedrock:[A-Za-z]+)`)

func (e *APIError) accessDenied() bool {
	if e.Status != http.StatusForbidden {
		return false
	}
	if e.ErrorType != "" {
		return e.ErrorType == "AccessDeniedException" || e.ErrorType == "AccessDenied"
	}
	// No error name from AWS: only AWS's own IAM denial wording counts.
	return notAuthorizedAction.MatchString(e.Body)
}

// MissingPermission reports whether err is an IAM denial (an AccessDenied 403)
// and, when it can tell, the action that was denied. The action comes from AWS's
// own message, and otherwise from the endpoint called. Every other failure —
// invalid or expired credentials (UnrecognizedClient, InvalidSignature,
// ExpiredToken), throttling, 5xx, network — returns ("", false): it says nothing
// about permissions and must not be reported or remembered as one.
func MissingPermission(err error) (string, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.accessDenied() {
		return "", false
	}
	if m := notAuthorizedAction.FindStringSubmatch(apiErr.Body); m != nil {
		return m[1], true
	}
	switch {
	case apiErr.Path == foundationModelsPath:
		return "bedrock:ListFoundationModels", true
	case apiErr.Path == inferenceProfilesPath:
		return "bedrock:ListInferenceProfiles", true
	case strings.HasPrefix(apiErr.Path, availabilityPath):
		return "bedrock:GetFoundationModelAvailability", true
	}
	return "", true
}

func (c *client) CheckCatalogAccess(ctx context.Context, creds Credentials) ([]string, error) {
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

	var missing []string
	record := func(action string, err error) error {
		if err == nil {
			return nil
		}
		if got, denied := MissingPermission(err); denied {
			if got == "" {
				got = action
			}
			if !slices.Contains(missing, got) {
				missing = append(missing, got)
			}
			return nil
		}
		return err
	}

	var models foundationModelsResponse
	if err := record("bedrock:ListFoundationModels",
		c.get(ctx, awsCreds, creds.Region, foundationModelsPath, nil, &models)); err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("type", profileTypeSystemDefined)
	query.Set("maxResults", "1")
	var profiles inferenceProfilesResponse
	if err := record("bedrock:ListInferenceProfiles",
		c.get(ctx, awsCreds, creds.Region, inferenceProfilesPath, query, &profiles)); err != nil {
		return nil, err
	}

	// Availability needs a real model ID to ask about: one ListInvocableModelIDs
	// could itself offer (ON_DEMAND) and that is not retired. Without one the
	// permission is simply not probed. A failure that is not a permission denial
	// also means "not probed": it must not discard the listing results above.
	for _, summary := range models.ModelSummaries {
		if summary.ModelID == "" || !slices.Contains(summary.InferenceTypesSupported, inferenceTypeOnDemand) {
			continue
		}
		if status := summary.ModelLifecycle.Status; status != "" && status != "ACTIVE" {
			continue
		}
		var payload availabilityResponse
		err := c.get(ctx, awsCreds, creds.Region, availabilityPath+url.PathEscape(summary.ModelID), nil, &payload)
		if action, denied := MissingPermission(err); denied {
			if action == "" {
				action = "bedrock:GetFoundationModelAvailability"
			}
			if !slices.Contains(missing, action) {
				missing = append(missing, action)
			}
		}
		break
	}
	return missing, nil
}
