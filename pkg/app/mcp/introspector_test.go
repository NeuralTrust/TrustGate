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

package mcp

import (
	"context"
	"errors"
	"testing"

	regmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func introspectableRegistry(gwID ids.GatewayID, regID ids.RegistryID) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        regID,
		GatewayID: gwID,
		Name:      "shared-server",
		Type:      registrydomain.TypeMCP,
		Enabled:   true,
		MCPTarget: &registrydomain.MCPTarget{
			URL:       "https://mcp.example.com",
			Transport: registrydomain.MCPTransportStreamableHTTP,
			Auth:      &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer t"},
		},
	}
}

func newIntrospectorFor(t *testing.T, reg *registrydomain.Registry, dialer Dialer) Introspector {
	t.Helper()
	finder := regmocks.NewFinder(t)
	finder.EXPECT().
		FindByID(mock.Anything, reg.GatewayID, reg.ID).
		Return(reg, nil).
		Once()
	return NewIntrospector(finder, dialer)
}

func TestIntrospector_ListRegistryTools_OK(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	regID := ids.New[ids.RegistryKind]()
	reg := introspectableRegistry(gwID, regID)
	up := &fakeUpstream{tools: []Tool{{Name: "search"}, {Name: "create_issue"}}}

	sut := newIntrospectorFor(t, reg, DialerFunc(func(context.Context, Target) (Upstream, error) {
		return up, nil
	}))

	tools, err := sut.ListRegistryTools(context.Background(), gwID, regID)
	require.NoError(t, err)
	require.Len(t, tools, 2)
	assert.Equal(t, "search", tools[0].Name)
	assert.Equal(t, "create_issue", tools[1].Name)
}

func TestIntrospector_ListRegistryTools_ListToolsFailureIsUpstreamUnavailable(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	regID := ids.New[ids.RegistryKind]()
	reg := introspectableRegistry(gwID, regID)
	listErr := errors.New("tools/list: rpc error -32603")
	up := &fakeUpstream{listErr: listErr}

	sut := newIntrospectorFor(t, reg, DialerFunc(func(context.Context, Target) (Upstream, error) {
		return up, nil
	}))

	tools, err := sut.ListRegistryTools(context.Background(), gwID, regID)
	require.Error(t, err)
	assert.Nil(t, tools)
	assert.True(t, errors.Is(err, ErrUpstreamUnavailable), "tools/list failure must map to 502, not 500")
	assert.True(t, errors.Is(err, listErr), "the upstream cause must stay readable")
}

func TestIntrospector_ListRegistryTools_ConnectFailureIsUpstreamUnavailable(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	regID := ids.New[ids.RegistryKind]()
	reg := introspectableRegistry(gwID, regID)

	sut := newIntrospectorFor(t, reg, DialerFunc(func(context.Context, Target) (Upstream, error) {
		return nil, ErrUnreachable
	}))

	_, err := sut.ListRegistryTools(context.Background(), gwID, regID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUpstreamUnavailable))
}

func TestIntrospector_ListRegistryTools_NotIntrospectable(t *testing.T) {
	perPrincipalAuthTarget := func(mode registrydomain.MCPAuthMode) *registrydomain.MCPAuth {
		return &registrydomain.MCPAuth{Mode: mode}
	}
	urlVariables := []registrydomain.MCPURLVariable{{Name: "instance", Required: true}}

	tests := []struct {
		name         string
		auth         *registrydomain.MCPAuth
		urlVariables []registrydomain.MCPURLVariable
	}{
		{
			name: "per-principal auth alone",
			auth: perPrincipalAuthTarget(registrydomain.MCPAuthModePassthrough),
		},
		{
			name: "exchange auth alone",
			auth: perPrincipalAuthTarget(registrydomain.MCPAuthModeExchange),
		},
		{
			name: "forwarded auth alone",
			auth: perPrincipalAuthTarget(registrydomain.MCPAuthModeForwarded),
		},
		{
			name:         "url variables alone",
			auth:         &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic},
			urlVariables: urlVariables,
		},
		{
			name:         "per-principal auth and url variables combined",
			auth:         perPrincipalAuthTarget(registrydomain.MCPAuthModePassthrough),
			urlVariables: urlVariables,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gwID := ids.New[ids.GatewayKind]()
			regID := ids.New[ids.RegistryKind]()
			reg := introspectableRegistry(gwID, regID)
			reg.MCPTarget.Auth = tc.auth
			reg.MCPTarget.URLVariables = tc.urlVariables

			sut := newIntrospectorFor(t, reg, DialerFunc(func(context.Context, Target) (Upstream, error) {
				t.Fatal("dialer must not be reached for a registry that needs a principal")
				return nil, nil
			}))

			tools, err := sut.ListRegistryTools(context.Background(), gwID, regID)
			require.Error(t, err)
			assert.Nil(t, tools)
			assert.True(t, errors.Is(err, ErrRegistryNotIntrospectable))
			assert.True(t, errors.Is(err, commonerrors.ErrConflict), "the sentinel must answer 409, not 422")
			assert.False(t, errors.Is(err, ErrUpstreamUnavailable))
		})
	}
}

func TestIntrospector_ListRegistryTools_IntrospectableAuthModes(t *testing.T) {
	for _, mode := range []registrydomain.MCPAuthMode{
		registrydomain.MCPAuthModeNone,
		registrydomain.MCPAuthModeStatic,
		registrydomain.MCPAuthModeClientCredentials,
	} {
		t.Run(string(mode), func(t *testing.T) {
			gwID := ids.New[ids.GatewayKind]()
			regID := ids.New[ids.RegistryKind]()
			reg := introspectableRegistry(gwID, regID)
			reg.MCPTarget.Auth = &registrydomain.MCPAuth{Mode: mode}

			sut := newIntrospectorFor(t, reg, DialerFunc(func(context.Context, Target) (Upstream, error) {
				return &fakeUpstream{tools: []Tool{{Name: "search"}}}, nil
			}))

			tools, err := sut.ListRegistryTools(context.Background(), gwID, regID)
			require.NoError(t, err)
			require.Len(t, tools, 1)
		})
	}
}

func TestIntrospector_ListRegistryTools_NotAnMCPRegistry(t *testing.T) {
	gwID := ids.New[ids.GatewayKind]()
	regID := ids.New[ids.RegistryKind]()
	reg := introspectableRegistry(gwID, regID)
	reg.Type = registrydomain.TypeLLM

	sut := newIntrospectorFor(t, reg, DialerFunc(func(context.Context, Target) (Upstream, error) {
		t.Fatal("dialer must not be reached for a non-MCP registry")
		return nil, nil
	}))

	_, err := sut.ListRegistryTools(context.Background(), gwID, regID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoMCPRegistries))
}
