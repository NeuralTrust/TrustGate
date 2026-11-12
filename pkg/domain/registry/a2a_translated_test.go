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

package registry_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const testHarnessARN = "arn:aws:bedrock-agentcore:us-east-1:888577023128:harness/harness_0m4lj-8nAuuzxT1b"

func harnessTarget() *registry.A2ATarget {
	return &registry.A2ATarget{
		Provider:         registry.A2AProviderAgentCoreHarness,
		AgentCoreHarness: &registry.HarnessLocator{HarnessARN: testHarnessARN},
		Auth:             &registry.MCPAuth{Mode: registry.A2AAuthModeCloud},
		CloudAuth:        &registry.A2ACloudAuth{AWS: &registry.A2AAWSAuth{AWSAuth: registry.AWSAuth{AccessKeyID: "AKIA", SecretAccessKey: "s"}}},
	}
}

func TestHarnessLocator(t *testing.T) {
	t.Parallel()
	target := harnessTarget()
	target.Normalize()
	require.NoError(t, target.Validate())
	assert.Equal(t, "us-east-1", target.AWSRegion())
	assert.Equal(t, "harness_0m4lj", target.AgentCoreHarness.Name())
	assert.Equal(t, "https://bedrock-agentcore.us-east-1.amazonaws.com/harnesses/invoke?harnessArn="+
		"arn%3Aaws%3Abedrock-agentcore%3Aus-east-1%3A888577023128%3Aharness%2Fharness_0m4lj-8nAuuzxT1b&qualifier=DEFAULT", target.Endpoint())

	runtime := harnessTarget()
	runtime.AgentCoreHarness.HarnessARN = "arn:aws:bedrock-agentcore:us-east-1:888577023128:runtime/harness_harness_0m4lj-RPK2585ENp"
	assert.ErrorIs(t, runtime.Validate(), registry.ErrInvalidRegistry, "a runtime ARN is not a harness")

	static := harnessTarget()
	static.Auth = &registry.MCPAuth{Mode: registry.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer x"}
	static.CloudAuth = nil
	assert.ErrorIs(t, static.Validate(), registry.ErrInvalidRegistry, "a harness signs in with AWS only")
}

func TestDatabricksLocator(t *testing.T) {
	t.Parallel()
	serving := &registry.A2ATarget{
		Provider:   registry.A2AProviderDatabricks,
		Databricks: &registry.DatabricksLocator{WorkspaceURL: "https://adb-1.2.azuredatabricks.net/", ServingEndpoint: "agents_flats"},
		Auth:       &registry.MCPAuth{Mode: registry.MCPAuthModeClientCredentials, ClientID: "sp", ClientSecret: "secret"},
	}
	serving.Normalize()
	require.NoError(t, serving.Validate())
	assert.Equal(t, "https://adb-1.2.azuredatabricks.net/serving-endpoints/agents_flats/invocations", serving.Endpoint())
	assert.Equal(t, "https://adb-1.2.azuredatabricks.net/oidc/v1/token", serving.Auth.TokenURL, "the workspace issues a service principal's token")
	assert.Equal(t, "all-apis", serving.Auth.Scope)

	app := &registry.A2ATarget{
		Provider:   registry.A2AProviderDatabricks,
		Databricks: &registry.DatabricksLocator{WorkspaceURL: "https://acme.cloud.databricks.com", AppURL: "https://flats-123.aws.databricksapps.com"},
		Auth:       &registry.MCPAuth{Mode: registry.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer dapi"},
	}
	app.Normalize()
	require.NoError(t, app.Validate())
	assert.Equal(t, "https://flats-123.aws.databricksapps.com/responses", app.Endpoint())
	assert.Equal(t, "flats-123", app.Databricks.Name())

	for name, locator := range map[string]*registry.DatabricksLocator{
		"both":           {WorkspaceURL: "https://acme.cloud.databricks.com", ServingEndpoint: "a", AppURL: "https://a.databricksapps.com"},
		"neither":        {WorkspaceURL: "https://acme.cloud.databricks.com"},
		"no workspace":   {ServingEndpoint: "a"},
		"workspace path": {WorkspaceURL: "https://acme.cloud.databricks.com/serving-endpoints", ServingEndpoint: "a"},
		"foreign app":    {WorkspaceURL: "https://acme.cloud.databricks.com", AppURL: "https://evil.example.com"},
	} {
		target := &registry.A2ATarget{Provider: registry.A2AProviderDatabricks, Databricks: locator, Auth: &registry.MCPAuth{Mode: registry.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer dapi"}}
		target.Normalize()
		assert.ErrorIs(t, target.Validate(), registry.ErrInvalidRegistry, name)
	}
}

// The gateway builds the card of an agent that publishes none, and it pins
// like any other: A2A 0.3, no streaming.
func TestBuiltCardPins(t *testing.T) {
	t.Parallel()
	target := harnessTarget()
	target.Normalize()
	require.True(t, target.Provider.BuildsCard())
	require.NoError(t, target.Pin("", target.BuiltCard(), time.Now()))
	assert.Equal(t, registry.A2AVersion03, target.ProtocolVersion)

	var card struct {
		Name         string `json:"name"`
		Capabilities struct {
			Streaming bool `json:"streaming"`
		} `json:"capabilities"`
		Skills []struct {
			ID string `json:"id"`
		} `json:"skills"`
	}
	require.NoError(t, json.Unmarshal(target.Card, &card))
	assert.Equal(t, "harness_0m4lj", card.Name)
	assert.False(t, card.Capabilities.Streaming)
	assert.Len(t, card.Skills, 1)

	target.ProtocolVersion = registry.A2AVersion10
	assert.ErrorIs(t, target.Validate(), registry.ErrAgentVersionUnsupported)
}
