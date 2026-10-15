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

package oauth

import (
	"context"
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type recordingRegistrar struct{ discovered []string }

func (r *recordingRegistrar) Discover(_ context.Context, upstreamURL string) (*UpstreamAuthServer, error) {
	r.discovered = append(r.discovered, upstreamURL)
	return &UpstreamAuthServer{}, nil
}

func (r *recordingRegistrar) EnsureClient(context.Context, string, *UpstreamAuthServer, string) (*RegisteredClient, error) {
	return &RegisteredClient{}, nil
}

func (r *recordingRegistrar) CachedClient(context.Context, string) (*RegisteredClient, error) {
	return nil, nil
}

type staticURLValues map[string]map[string]string

func (v staticURLValues) Values(_ context.Context, _ ids.GatewayID, principalSub string, _ *registrydomain.Registry) (map[string]string, error) {
	return v[principalSub], nil
}

func awsRegistry() *registrydomain.Registry {
	return &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		Code:         "com.amazon.aws/mcp",
		URL:          "https://aws-mcp.{region}.api.aws/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{Name: "region", Required: true}},
	}}
}

// RUN-1636: discovery was handed the template, so every {variable} server failed
// with "bad upstream url" however its values had been given.
func TestDiscoverResolvesTheTemplateForThePrincipal(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar, urlValues: staticURLValues{"ana": {"region": "eu-west-1"}}}

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", awsRegistry()); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(registrar.discovered) != 1 || registrar.discovered[0] != "https://aws-mcp.eu-west-1.api.aws/mcp" {
		t.Fatalf("discovered %v, want the resolved URL", registrar.discovered)
	}
}

func TestDiscoverReadsARegistryThatCarriesItsOwnValues(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar}
	reg := awsRegistry()
	reg.MCPTarget.InstanceConfig = map[string]string{"region": "us-east-1"}

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if registrar.discovered[0] != "https://aws-mcp.us-east-1.api.aws/mcp" {
		t.Fatalf("discovered %v", registrar.discovered)
	}
}

func TestDiscoverAsksForSetupWhenAValueIsMissing(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar, urlValues: staticURLValues{}}

	_, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", awsRegistry())
	if !errors.Is(err, ErrUpstreamSetupRequired) || !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("want ErrUpstreamSetupRequired (validation), got %v", err)
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("nothing may be fetched without an address, discovered %v", registrar.discovered)
	}
}

// Discovery fetches from the resolved host, so it is held to the dial path's
// SSRF gate: a value cannot point it at the cluster.
func TestDiscoverRefusesAPrivateResolvedHost(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar, urlValues: staticURLValues{"ana": {"domain": "localhost"}}}
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{
		URL:          "https://{domain}/mcp",
		URLVariables: []registrydomain.MCPURLVariable{{Name: "domain", Required: true}},
	}}

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "ana", reg); err == nil {
		t.Fatal("want the resolved host refused")
	}
	if len(registrar.discovered) != 0 {
		t.Fatalf("discovered %v, want nothing fetched", registrar.discovered)
	}
}

func TestDiscoverLeavesAFixedURLAlone(t *testing.T) {
	registrar := &recordingRegistrar{}
	s := &connectService{registrar: registrar}
	reg := &registrydomain.Registry{MCPTarget: &registrydomain.MCPTarget{URL: "https://mcp.linear.app/mcp"}}

	if _, err := s.discover(context.Background(), ids.New[ids.GatewayKind](), "", reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if registrar.discovered[0] != "https://mcp.linear.app/mcp" {
		t.Fatalf("discovered %v", registrar.discovered)
	}
}
