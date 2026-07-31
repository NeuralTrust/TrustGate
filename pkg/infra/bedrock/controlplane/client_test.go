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

const testCredentials = `{
	"modelSummaries": [
		{"modelId": "anthropic.claude-sonnet-4-5-20250929-v1:0", "inferenceTypesSupported": ["INFERENCE_PROFILE"]},
		{"modelId": "amazon.nova-pro-v1:0", "inferenceTypesSupported": ["ON_DEMAND", "PROVISIONED"]},
		{"modelId": "amazon.titan-tg1-large", "inferenceTypesSupported": ["PROVISIONED"]},
		{"modelId": "", "inferenceTypesSupported": ["ON_DEMAND"]}
	]
}`

func newTestClient(t *testing.T, handler http.Handler) (Client, *httptest.Server) {
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
	}, server
}

func TestListServerlessModelIDs_KeepsOnDemandAndProfilesOnly(t *testing.T) {
	t.Parallel()
	var paths []string
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case foundationModelsPath:
			_, _ = w.Write([]byte(testCredentials))
		case inferenceProfilesPath:
			assert.Equal(t, profileTypeSystemDefined, r.URL.Query().Get("type"))
			_, _ = w.Write([]byte(`{"inferenceProfileSummaries": [
				{"inferenceProfileId": "eu.anthropic.claude-sonnet-4-5-20250929-v1:0", "status": "ACTIVE", "type": "SYSTEM_DEFINED"},
				{"inferenceProfileId": "us.anthropic.retired-v1:0", "status": "INACTIVE", "type": "SYSTEM_DEFINED"}
			]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	c, _ := newTestClient(t, handler)

	got, err := c.ListServerlessModelIDs(context.Background(), Credentials{Region: "eu-west-1"})
	require.NoError(t, err)

	want := map[string]struct{}{
		// Reachable through its inference profile, so the model stays listed.
		"anthropic.claude-sonnet-4-5-20250929-v1:0": {},
		"amazon.nova-pro-v1:0":                      {},
		"eu.anthropic.claude-sonnet-4-5-20250929-v1:0": {},
	}
	assert.Equal(t, want, got)
	assert.ElementsMatch(t, []string{foundationModelsPath, inferenceProfilesPath}, paths)
}

func TestListServerlessModelIDs_SignsRequests(t *testing.T) {
	t.Parallel()
	var authorization string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == foundationModelsPath {
			authorization = r.Header.Get("Authorization")
		}
		_, _ = w.Write([]byte(`{}`))
	})
	c, _ := newTestClient(t, handler)

	_, err := c.ListServerlessModelIDs(context.Background(), Credentials{Region: "us-east-1"})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 "), "got %q", authorization)
	assert.Contains(t, authorization, "/us-east-1/bedrock/aws4_request")
}

func TestListServerlessModelIDs_FollowsProfilePagination(t *testing.T) {
	t.Parallel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == foundationModelsPath {
			_, _ = w.Write([]byte(`{"modelSummaries": []}`))
			return
		}
		if r.URL.Query().Get("nextToken") == "" {
			_, _ = w.Write([]byte(`{"inferenceProfileSummaries": [
				{"inferenceProfileId": "us.first-v1:0", "status": "ACTIVE"}
			], "nextToken": "page-2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"inferenceProfileSummaries": [
			{"inferenceProfileId": "us.second-v1:0", "status": "ACTIVE"}
		]}`))
	})
	c, _ := newTestClient(t, handler)

	got, err := c.ListServerlessModelIDs(context.Background(), Credentials{Region: "us-east-1"})
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"us.first-v1:0": {}, "us.second-v1:0": {}}, got)
}

// A repeating nextToken must not loop forever.
func TestListServerlessModelIDs_StopsOnRepeatedToken(t *testing.T) {
	t.Parallel()
	var calls int
	var mu sync.Mutex
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == foundationModelsPath {
			_, _ = w.Write([]byte(`{"modelSummaries": []}`))
			return
		}
		mu.Lock()
		calls++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"inferenceProfileSummaries": [
			{"inferenceProfileId": "us.loop-v1:0", "status": "ACTIVE"}
		], "nextToken": "same"}`))
	})
	c, _ := newTestClient(t, handler)

	got, err := c.ListServerlessModelIDs(context.Background(), Credentials{Region: "us-east-1"})
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"us.loop-v1:0": {}}, got)
	assert.Equal(t, 2, calls, "should stop as soon as the token repeats")
}

func TestListServerlessModelIDs_PropagatesAWSError(t *testing.T) {
	t.Parallel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"not authorized to perform bedrock:ListFoundationModels"}`))
	})
	c, _ := newTestClient(t, handler)

	_, err := c.ListServerlessModelIDs(context.Background(), Credentials{Region: "us-east-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "bedrock:ListFoundationModels")
}

func TestListServerlessModelIDs_RequiresRegion(t *testing.T) {
	t.Parallel()
	c := NewClient()
	_, err := c.ListServerlessModelIDs(context.Background(), Credentials{})
	assert.True(t, errors.Is(err, ErrRegionRequired))
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
