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

package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const foundationModelsPayload = `{
	"modelSummaries": [
		{"modelId": "anthropic.claude-sonnet-4-5-20250929-v1:0", "inferenceTypesSupported": ["INFERENCE_PROFILE"]},
		{"modelId": "amazon.nova-pro-v1:0", "inferenceTypesSupported": ["ON_DEMAND", "PROVISIONED"]},
		{"modelId": "amazon.titan-tg1-large", "inferenceTypesSupported": ["PROVISIONED"]},
		{"modelId": "", "inferenceTypesSupported": ["ON_DEMAND"]}
	]
}`

const profilesPayload = `{"inferenceProfileSummaries": [
	{"inferenceProfileId": "eu.anthropic.claude-sonnet-4-5-20250929-v1:0", "status": "ACTIVE", "type": "SYSTEM_DEFINED"},
	{"inferenceProfileId": "us.anthropic.retired-v1:0", "status": "INACTIVE", "type": "SYSTEM_DEFINED"}
]}`

func entitledPayload(agreement, authorized, entitled, region bool) string {
	status := func(ok bool, yes, no string) string {
		if ok {
			return yes
		}
		return no
	}
	return `{"agreementAvailability": {"status": "` + status(agreement, "AVAILABLE", "NOT_AVAILABLE") +
		`"}, "authorizationStatus": "` + status(authorized, "AUTHORIZED", "NOT_AUTHORIZED") +
		`", "entitlementAvailability": "` + status(entitled, "AVAILABLE", "NOT_AVAILABLE") +
		`", "regionAvailability": "` + status(region, "AVAILABLE", "NOT_AVAILABLE") + `"}`
}

func newTestClient(t *testing.T, handler http.Handler) Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &client{
		httpClient: server.Client(),
		signer:     v4.NewSigner(),
		loadConfig: func(_ context.Context, creds Credentials) (aws.Config, error) {
			return aws.Config{
				Region: creds.Region,
				Credentials: awscredentials.NewStaticCredentialsProvider(
					"AKIAEXAMPLE", "secret", "",
				),
			}, nil
		},
		endpoint: server.URL,
	}
}

// catalogHandler serves the two list endpoints, and delegates availability to
// entitlement so each test decides which models the account may invoke.
func catalogHandler(entitlement func(modelID string) (int, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == foundationModelsPath:
			_, _ = w.Write([]byte(foundationModelsPayload))
		case r.URL.Path == inferenceProfilesPath:
			_, _ = w.Write([]byte(profilesPayload))
		case strings.HasPrefix(r.URL.Path, availabilityPath):
			status, body := entitlement(strings.TrimPrefix(r.URL.Path, availabilityPath))
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func allEntitled(string) (int, string) {
	return http.StatusOK, entitledPayload(true, true, true, true)
}

func TestListInvocableModelIDs_KeepsServerlessAndEntitledOnly(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, catalogHandler(allEntitled))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "eu-west-1"}, []string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"amazon.nova-pro-v1:0",
		"amazon.titan-tg1-large", // PROVISIONED only.
		"google.gemma-3-4b-it",   // Marketplace: absent from the region listing.
		"us.anthropic.retired-v1:0",
	})
	require.NoError(t, err)

	assert.True(t, got.EntitlementChecked)
	assert.Equal(t, map[string]struct{}{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0": {},
		"amazon.nova-pro-v1:0":                         {},
	}, got.ModelIDs)
}

// The account sees the model in the region but has not enabled access to it —
// invoking it would fail with AccessDeniedException, so it must not be listed.
func TestListInvocableModelIDs_DropsModelsWithoutAccess(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, catalogHandler(func(modelID string) (int, string) {
		if strings.HasPrefix(modelID, "anthropic.") {
			return http.StatusOK, entitledPayload(true, true, false, true)
		}
		return allEntitled(modelID)
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "eu-west-1"}, []string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"amazon.nova-pro-v1:0",
	})
	require.NoError(t, err)

	assert.True(t, got.EntitlementChecked)
	assert.Equal(t, map[string]struct{}{"amazon.nova-pro-v1:0": {}}, got.ModelIDs)
}

// A real response from an account that never completed the model's AWS
// Marketplace subscription: authorization, entitlement and region all read
// positive and only agreementAvailability is negative. Invoking it still fails
// with AccessDeniedException, so agreementAvailability cannot be ignored.
func TestListInvocableModelIDs_DropsModelWithoutAgreement(t *testing.T) {
	t.Parallel()
	const noAgreement = `{
		"modelId": "anthropic.claude-sonnet-4-5-20250929-v1",
		"agreementAvailability": {"status": "NOT_AVAILABLE"},
		"authorizationStatus": "AUTHORIZED",
		"entitlementAvailability": "AVAILABLE",
		"regionAvailability": "AVAILABLE"
	}`
	c := newTestClient(t, catalogHandler(func(modelID string) (int, string) {
		if strings.HasPrefix(modelID, "anthropic.") {
			return http.StatusOK, noAgreement
		}
		return allEntitled(modelID)
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "eu-west-1"}, []string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"amazon.nova-pro-v1:0",
	})
	require.NoError(t, err)

	assert.True(t, got.EntitlementChecked)
	assert.Equal(t, map[string]struct{}{"amazon.nova-pro-v1:0": {}}, got.ModelIDs)
}

func TestListInvocableModelIDs_DropsUnauthorizedAndOutOfRegion(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, catalogHandler(func(modelID string) (int, string) {
		if strings.HasPrefix(modelID, "anthropic.") {
			return http.StatusOK, entitledPayload(true, false, true, true)
		}
		return http.StatusOK, entitledPayload(true, true, true, false)
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "eu-west-1"}, []string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"amazon.nova-pro-v1:0",
	})
	require.NoError(t, err)

	assert.True(t, got.EntitlementChecked)
	assert.Empty(t, got.ModelIDs)
}

// Entitlement lives on the base model, so one call covers every regional
// profile of it.
func TestListInvocableModelIDs_ChecksEntitlementOncePerBaseModel(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	asked := map[string]int{}
	c := newTestClient(t, catalogHandler(func(modelID string) (int, string) {
		mu.Lock()
		asked[modelID]++
		mu.Unlock()
		return allEntitled(modelID)
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "eu-west-1"}, []string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"anthropic.claude-sonnet-4-5-20250929-v1:0",
		"amazon.nova-pro-v1:0",
	})
	require.NoError(t, err)

	assert.Len(t, got.ModelIDs, 3)
	assert.Equal(t, map[string]int{
		"anthropic.claude-sonnet-4-5-20250929-v1:0": 1,
		"amazon.nova-pro-v1:0":                      1,
	}, asked)
}

// Without bedrock:GetFoundationModelAvailability nothing can be verified, so the
// serverless shortlist is returned and flagged as unverified rather than emptied.
func TestListInvocableModelIDs_ReportsUnverifiedEntitlement(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, catalogHandler(func(string) (int, string) {
		return http.StatusForbidden, `{"message":"not authorized to perform bedrock:GetFoundationModelAvailability"}`
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "eu-west-1"}, []string{
		"amazon.nova-pro-v1:0",
		"google.gemma-3-4b-it",
	})
	require.NoError(t, err)

	assert.False(t, got.EntitlementChecked)
	assert.Equal(t, map[string]struct{}{"amazon.nova-pro-v1:0": {}}, got.ModelIDs)
}

// One model erroring while others answer is treated as not entitled: the
// verdict set is trustworthy, so a lone failure should not be waved through.
func TestListInvocableModelIDs_DropsModelWhoseCheckFails(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, catalogHandler(func(modelID string) (int, string) {
		if strings.HasPrefix(modelID, "anthropic.") {
			return http.StatusNotFound, `{"message":"ResourceNotFoundException"}`
		}
		return allEntitled(modelID)
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "eu-west-1"}, []string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
		"amazon.nova-pro-v1:0",
	})
	require.NoError(t, err)

	assert.True(t, got.EntitlementChecked)
	assert.Equal(t, map[string]struct{}{"amazon.nova-pro-v1:0": {}}, got.ModelIDs)
}

func TestListInvocableModelIDs_SignsRequests(t *testing.T) {
	t.Parallel()
	var authorization string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == foundationModelsPath {
			authorization = r.Header.Get("Authorization")
		}
		_, _ = w.Write([]byte(`{}`))
	}))

	_, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "us-east-1"}, []string{"x.y-v1:0"})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 "), "got %q", authorization)
	assert.Contains(t, authorization, "/us-east-1/bedrock/aws4_request")
}

func TestListInvocableModelIDs_FollowsProfilePagination(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == foundationModelsPath:
			_, _ = w.Write([]byte(`{"modelSummaries": []}`))
		case strings.HasPrefix(r.URL.Path, availabilityPath):
			_, _ = w.Write([]byte(entitledPayload(true, true, true, true)))
		case r.URL.Query().Get("nextToken") == "":
			_, _ = w.Write([]byte(`{"inferenceProfileSummaries": [
				{"inferenceProfileId": "us.first-v1:0", "status": "ACTIVE"}
			], "nextToken": "page-2"}`))
		default:
			_, _ = w.Write([]byte(`{"inferenceProfileSummaries": [
				{"inferenceProfileId": "us.second-v1:0", "status": "ACTIVE"}
			]}`))
		}
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "us-east-1"},
		[]string{"us.first-v1:0", "us.second-v1:0"})
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"us.first-v1:0": {}, "us.second-v1:0": {}}, got.ModelIDs)
}

// A repeating nextToken must not loop forever.
func TestListInvocableModelIDs_StopsOnRepeatedToken(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var calls int
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == foundationModelsPath:
			_, _ = w.Write([]byte(`{"modelSummaries": []}`))
		case strings.HasPrefix(r.URL.Path, availabilityPath):
			_, _ = w.Write([]byte(entitledPayload(true, true, true, true)))
		default:
			mu.Lock()
			calls++
			mu.Unlock()
			_, _ = w.Write([]byte(`{"inferenceProfileSummaries": [
				{"inferenceProfileId": "us.loop-v1:0", "status": "ACTIVE"}
			], "nextToken": "same"}`))
		}
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "us-east-1"},
		[]string{"us.loop-v1:0"})
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"us.loop-v1:0": {}}, got.ModelIDs)
	assert.Equal(t, 2, calls, "should stop as soon as the token repeats")
}

func TestListInvocableModelIDs_PropagatesListingError(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"not authorized to perform bedrock:ListFoundationModels"}`))
	}))

	_, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "us-east-1"}, []string{"x.y-v1:0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "bedrock:ListFoundationModels")
}

func TestListInvocableModelIDs_RequiresRegion(t *testing.T) {
	t.Parallel()
	_, err := NewClient().ListInvocableModelIDs(context.Background(), Credentials{}, []string{"x.y-v1:0"})
	assert.True(t, errors.Is(err, ErrRegionRequired))
}

// No candidates means nothing to ask AWS about; the empty answer is authoritative.
func TestListInvocableModelIDs_ShortCircuitsWithoutCandidates(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("no control plane call expected")
	}))

	got, err := c.ListInvocableModelIDs(context.Background(), Credentials{Region: "us-east-1"}, nil)
	require.NoError(t, err)
	assert.True(t, got.EntitlementChecked)
	assert.Empty(t, got.ModelIDs)
}

func TestBaseModelID(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0":     "anthropic.claude-sonnet-4-5-20250929-v1:0",
		"global.anthropic.claude-sonnet-4-5-20250929-v1:0": "anthropic.claude-sonnet-4-5-20250929-v1:0",
		"us-gov.anthropic.claude-v1:0":                     "anthropic.claude-v1:0",
		"anthropic.claude-sonnet-4-5-20250929-v1:0":        "anthropic.claude-sonnet-4-5-20250929-v1:0",
		"amazon.nova-pro-v1:0":                             "amazon.nova-pro-v1:0",
		// "meta" is not a geography, so a three-segment ID keeps its first part.
		"meta.llama3.instruct-v1:0": "meta.llama3.instruct-v1:0",
	}
	for in, want := range cases {
		assert.Equal(t, want, baseModelID(in), in)
	}
}

func TestBaseURL(t *testing.T) {
	t.Parallel()
	c := &client{}
	assert.Equal(t, "https://bedrock.eu-west-1.amazonaws.com", c.baseURL("eu-west-1"))
	assert.Equal(t, "https://bedrock.cn-north-1.amazonaws.com.cn", c.baseURL("cn-north-1"))
	assert.Equal(t, "https://bedrock.us-gov-west-1.amazonaws.com", c.baseURL("us-gov-west-1"))

	override := &client{endpoint: "https://vpce-1234.bedrock.eu-west-1.vpce.amazonaws.com"}
	assert.Equal(t, "https://vpce-1234.bedrock.eu-west-1.vpce.amazonaws.com", override.baseURL("eu-west-1"))
}

func TestCredentialsCacheKey_OmitsSecret(t *testing.T) {
	t.Parallel()
	creds := Credentials{
		Region:    "eu-west-1",
		AccessKey: "AKIAEXAMPLE",
		SecretKey: "super-secret",
		UseRole:   true,
		RoleARN:   "arn:aws:iam::123456789012:role/bedrock",
	}
	key := creds.CacheKey()
	assert.NotContains(t, key, "super-secret")
	assert.Contains(t, key, "eu-west-1")
	assert.Contains(t, key, "AKIAEXAMPLE")

	other := creds
	other.Region = "us-east-1"
	assert.NotEqual(t, key, other.CacheKey())
}
