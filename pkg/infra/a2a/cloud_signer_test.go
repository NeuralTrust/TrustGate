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
	"net/http"
	"strings"
	"testing"

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
