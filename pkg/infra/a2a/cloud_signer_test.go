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

package a2a

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRuntimeARN = "arn:aws:bedrock-agentcore:eu-west-1:123456789012:runtime/travel-abc"

func agentCoreStatic() *domain.A2ATarget {
	t := &domain.A2ATarget{
		Provider:         domain.A2AProviderBedrockAgentCore,
		BedrockAgentCore: &domain.AgentCoreLocator{RuntimeARN: testRuntimeARN},
		Auth:             &domain.MCPAuth{Mode: domain.A2AAuthModeCloud},
		CloudAuth: &domain.A2ACloudAuth{AWS: &domain.A2AAWSAuth{AWSAuth: domain.AWSAuth{
			AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		}}},
	}
	t.Normalize()
	return t
}

func newRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	require.NoError(t, err)
	return req
}

func TestCloudSignerSendsTheCredentialOnlyToTheAgentHost(t *testing.T) {
	t.Parallel()
	target := agentCoreStatic()
	for _, url := range []string{
		"https://evil.example.com/runtimes/x/invocations/",
		"http://bedrock-agentcore.eu-west-1.amazonaws.com/runtimes/x/invocations/",
		"https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/x/invocations/",
	} {
		req := newRequest(t, http.MethodPost, url, `{}`)
		require.Error(t, NewCloudSigner().Sign(context.Background(), target, "", req), url)
		assert.Empty(t, req.Header.Get("Authorization"), url)
	}
}

type entraCredential struct {
	calls int
	exp   time.Time
}

func (c *entraCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.calls++
	if len(opts.Scopes) != 1 || opts.Scopes[0] != "https://ai.azure.com/.default" {
		return azcore.AccessToken{}, errors.New("unexpected scope")
	}
	return azcore.AccessToken{Token: "entra-" + strconv.Itoa(c.calls), ExpiresOn: c.exp}, nil
}

func TestCloudSignerKeepsTheEntraTokenUntilFiveMinutesBeforeItExpires(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	cred := &entraCredential{exp: now.Add(time.Hour)}
	s := NewCloudSigner()
	s.now = func() time.Time { return now }
	s.azureCredential = func(*domain.AzureAuth) (azcore.TokenCredential, error) { return cred, nil }
	target := &domain.A2ATarget{
		Provider:     domain.A2AProviderAzureFoundry,
		AzureFoundry: &domain.FoundryLocator{ProjectEndpoint: "https://acme.services.ai.azure.com/api/projects/travel", AgentName: "planner"},
		Auth:         &domain.MCPAuth{Mode: domain.A2AAuthModeCloud},
		CloudAuth:    &domain.A2ACloudAuth{Azure: &domain.AzureAuth{TenantID: "t", ClientID: "c", ClientSecret: "s"}},
	}
	sign := func(key string) string {
		req := newRequest(t, http.MethodPost, target.Endpoint(), `{}`)
		require.NoError(t, s.Sign(context.Background(), target, key, req))
		return req.Header.Get("Authorization")
	}

	assert.Equal(t, "Bearer entra-1", sign("reg-1"))
	now = now.Add(54 * time.Minute)
	assert.Equal(t, "Bearer entra-1", sign("reg-1"))
	now = now.Add(2 * time.Minute)
	assert.Equal(t, "Bearer entra-2", sign("reg-1"))
	assert.Equal(t, "Bearer entra-3", sign(""), "a preview keeps no token")
	assert.Equal(t, "Bearer entra-4", sign(""))
}
