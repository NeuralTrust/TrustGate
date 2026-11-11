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
	"context"
	"errors"
	"net/http"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func grantToken(token string) appregistry.ClientCredentialsGrant {
	return func(context.Context, *domain.MCPAuth) (string, error) { return token, nil }
}

func noCloud(t *testing.T) appregistry.CloudSigner {
	return func(context.Context, *domain.A2ATarget, *http.Request) error {
		t.Fatal("the cloud signer must not be used")
		return nil
	}
}

func cardRequest(t *testing.T, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err)
	return req
}

func agentCoreTarget(auth *domain.MCPAuth, cardAuth domain.A2ACardAuth) *domain.A2ATarget {
	t := &domain.A2ATarget{
		Provider:         domain.A2AProviderBedrockAgentCore,
		BedrockAgentCore: &domain.AgentCoreLocator{RuntimeARN: agentARN},
		Auth:             auth,
		CardAuth:         cardAuth,
	}
	t.Normalize()
	return t
}

func TestCardCredentialsGenericSameOnlyToTheCardHost(t *testing.T) {
	t.Parallel()
	target := &domain.A2ATarget{
		Provider: domain.A2AProviderGeneric,
		CardURL:  "https://travel.example.com/.well-known/agent-card.json",
		Auth:     &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "X-Key", Value: "k-1"},
		CardAuth: domain.A2ACardAuthSame,
	}
	authorize, err := appregistry.NewCardCredentials(grantToken("unused"), noCloud(t)).Authorizer(context.Background(), target)
	require.NoError(t, err)

	req := cardRequest(t, target.CardURL)
	require.NoError(t, authorize(req))
	assert.Equal(t, "k-1", req.Header.Get("X-Key"))

	foreign := cardRequest(t, "https://evil.example.com/.well-known/agent-card.json")
	require.ErrorIs(t, authorize(foreign), domain.ErrAgentCardUnavailable)
	assert.Empty(t, foreign.Header.Get("X-Key"))
}

func TestCardCredentialsGenericDefaultIsAnonymous(t *testing.T) {
	t.Parallel()
	target := &domain.A2ATarget{Provider: domain.A2AProviderGeneric, CardURL: "https://travel.example.com", Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeNone}}
	authorize, err := appregistry.NewCardCredentials(grantToken("unused"), noCloud(t)).Authorizer(context.Background(), target)
	require.NoError(t, err)
	assert.Nil(t, authorize)
}

func TestCardCredentialsHostedCloudUsesTheCloudSigner(t *testing.T) {
	t.Parallel()
	target := agentCoreTarget(&domain.MCPAuth{Mode: domain.A2AAuthModeCloud}, "")
	var signed *http.Request
	sign := func(_ context.Context, got *domain.A2ATarget, req *http.Request) error {
		assert.Same(t, target, got)
		signed = req
		return nil
	}
	authorize, err := appregistry.NewCardCredentials(grantToken("unused"), sign).Authorizer(context.Background(), target)
	require.NoError(t, err)
	req := cardRequest(t, target.CardLocation())
	require.NoError(t, authorize(req))
	assert.Same(t, req, signed)
}

func TestCardCredentialsHostedCloudFailureIsCardUnavailable(t *testing.T) {
	t.Parallel()
	target := agentCoreTarget(&domain.MCPAuth{Mode: domain.A2AAuthModeCloud}, "")
	sign := func(context.Context, *domain.A2ATarget, *http.Request) error { return errors.New("no credentials") }
	authorize, err := appregistry.NewCardCredentials(grantToken("unused"), sign).Authorizer(context.Background(), target)
	require.NoError(t, err)
	require.ErrorIs(t, authorize(cardRequest(t, target.CardLocation())), domain.ErrAgentCardUnavailable)
}

func TestCardCredentialsAgentCoreExchangeReadsWithClientCredentials(t *testing.T) {
	t.Parallel()
	target := agentCoreTarget(&domain.MCPAuth{
		Mode: domain.MCPAuthModeExchange, Pattern: domain.ExchangeTokenExchange,
		ClientID: "c", ClientSecret: "s", TokenURL: "https://idp.example.com/token",
	}, domain.A2ACardAuthClientCredentials)
	authorize, err := appregistry.NewCardCredentials(grantToken("app-token"), noCloud(t)).Authorizer(context.Background(), target)
	require.NoError(t, err)

	req := cardRequest(t, target.CardLocation())
	require.NoError(t, authorize(req))
	assert.Equal(t, "Bearer app-token", req.Header.Get("Authorization"))

	foreign := cardRequest(t, "https://bedrock-agentcore.us-east-1.amazonaws.com/x")
	require.ErrorIs(t, authorize(foreign), domain.ErrAgentCardUnavailable)
	assert.Empty(t, foreign.Header.Get("Authorization"))
}
