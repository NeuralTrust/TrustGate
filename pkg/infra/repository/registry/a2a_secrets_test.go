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

package registry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func a2aCredentialTarget() *domain.A2ATarget {
	return &domain.A2ATarget{
		Provider:         domain.A2AProviderBedrockAgentCore,
		BedrockAgentCore: &domain.AgentCoreLocator{RuntimeARN: "arn:aws:bedrock-agentcore:eu-west-1:123456789012:runtime/a", Qualifier: "DEFAULT"},
		Headers:          map[string]string{"X-Tenant": "header-secret"},
		Auth:             &domain.MCPAuth{Mode: domain.A2AAuthModeCloud},
		CloudAuth: &domain.A2ACloudAuth{AWS: &domain.A2AAWSAuth{
			AWSAuth: domain.AWSAuth{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "aws-secret", SessionToken: "aws-session"},
		}},
	}
}

func TestMarshalA2ATargetSealsEverySecret(t *testing.T) {
	t.Parallel()
	r := sealingRepo(t, true)
	id := ids.New[ids.RegistryKind]()
	in := a2aCredentialTarget()

	raw, err := r.marshalA2ATarget(id, in)
	require.NoError(t, err)
	for _, plain := range []string{"header-secret", "aws-secret", "aws-session"} {
		assert.NotContains(t, string(raw), plain)
	}
	assert.Equal(t, "aws-secret", in.CloudAuth.AWS.SecretAccessKey, "marshal must not modify the domain object")
	assert.Equal(t, "header-secret", in.Headers["X-Tenant"])

	var stored domain.A2ATarget
	require.NoError(t, json.Unmarshal(raw, &stored))
	r.openA2ATargetForRead(context.Background(), id, &stored)
	assert.Equal(t, "header-secret", stored.Headers["X-Tenant"])
	assert.Equal(t, "aws-secret", stored.CloudAuth.AWS.SecretAccessKey)
	assert.Equal(t, "aws-session", stored.CloudAuth.AWS.SessionToken)
	assert.False(t, stored.CloudAuth.SecretUnreadable)
}

func TestMarshalA2ATargetSealsAuthSecrets(t *testing.T) {
	t.Parallel()
	r := sealingRepo(t, true)
	id := ids.New[ids.RegistryKind]()
	in := &domain.A2ATarget{
		CardURL: "https://agent.example.com",
		Auth:    &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "X-Key", Value: "static-secret"},
	}
	raw, err := r.marshalA2ATarget(id, in)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "static-secret")

	var stored domain.A2ATarget
	require.NoError(t, json.Unmarshal(raw, &stored))
	r.openA2ATargetForRead(context.Background(), id, &stored)
	assert.Equal(t, "static-secret", stored.Auth.Value)
}

func TestOpenA2ATargetForReadMarksUnreadable(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.RegistryKind]()
	raw, err := sealingRepo(t, true).marshalA2ATarget(id, a2aCredentialTarget())
	require.NoError(t, err)

	var stored domain.A2ATarget
	require.NoError(t, json.Unmarshal(raw, &stored))
	other := &Repository{}
	WithFieldSealer(newSealer(t, "another-secret-0123456789abcdef-xyz"), true)(other)
	other.openA2ATargetForRead(context.Background(), id, &stored)

	assert.Empty(t, stored.CloudAuth.AWS.SecretAccessKey)
	assert.True(t, stored.CloudAuth.SecretUnreadable)
	assert.Equal(t, []string{"X-Tenant"}, stored.UnreadableHeaders)
}

func TestMarshalA2ATargetPlainWhenEncryptionOff(t *testing.T) {
	t.Parallel()
	raw, err := sealingRepo(t, false).marshalA2ATarget(ids.New[ids.RegistryKind](), a2aCredentialTarget())
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(raw), "aws-secret"))
}
