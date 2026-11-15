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

package secretref

import (
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// Hosts that receive a credential besides the entity's own upstream: the
// identity providers that exchange it for a token.
const (
	entraLoginHost  = "login.microsoftonline.com"
	googleTokenHost = "oauth2.googleapis.com" // #nosec G101 -- a public host name, not a credential
)

// hostList returns the normalized, non-empty hosts of raws, without
// duplicates. A raw value with no host is dropped, so a location whose
// destination is missing ends with fewer hosts, or none, and fails closed.
func hostList(raws ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range raws {
		h := secretstore.NormalizeHost(raw)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// allOrNone returns hostList(raws...) only when every raw has a host: a
// credential sent to two hosts, one of them unknown, has no complete list.
func allOrNone(raws ...string) []string {
	for _, raw := range raws {
		if secretstore.NormalizeHost(raw) == "" {
			return nil
		}
	}
	return hostList(raws...)
}

// llmUpstream is the host an LLM target calls: its base_url, or the
// provider's own.
func llmUpstream(t *registry.LLMTarget) string {
	if v, ok := t.ProviderOptions["base_url"].(string); ok && strings.TrimSpace(v) != "" && provider.HonorsBaseURL(t.Provider) {
		return v
	}
	switch t.Provider {
	case provider.Vertex:
		location, _ := t.ProviderOptions["location"].(string)
		return provider.VertexHost(strings.ToLower(strings.TrimSpace(location)))
	case provider.Bedrock:
		if t.Auth != nil && t.Auth.AWS != nil && t.Auth.AWS.Region != "" {
			return "bedrock-runtime." + t.Auth.AWS.Region + ".amazonaws.com"
		}
		return ""
	case provider.Azure:
		if t.Auth != nil && t.Auth.Azure != nil {
			return t.Auth.Azure.Endpoint
		}
		return ""
	case provider.Watsonx:
		region, _ := t.ProviderOptions["region"].(string)
		return provider.WatsonxHost(strings.ToLower(strings.TrimSpace(region)))
	}
	return provider.DefaultHost(t.Provider)
}

// llmHosts returns where the credential at path of an LLM target is sent.
func llmHosts(t *registry.LLMTarget, path []string) []string {
	upstream := llmUpstream(t)
	if len(path) < 3 {
		return nil
	}
	// A watsonx credential is an IBM Cloud API key: IAM receives it and
	// returns the bearer token the upstream receives.
	if t.Provider == provider.Watsonx {
		return allOrNone(upstream, provider.WatsonxIAMHost)
	}
	switch path[2] {
	case "aws":
		hosts := []string{upstream}
		if a := t.Auth.AWS; a.UseRole && a.Region != "" {
			hosts = append(hosts, "sts."+a.Region+".amazonaws.com")
		}
		if t.Provider == provider.Bedrock && t.Auth.AWS.Region != "" {
			hosts = append(hosts, "bedrock."+t.Auth.AWS.Region+".amazonaws.com")
		}
		return allOrNone(hosts...)
	case "azure":
		if len(path) > 3 && path[3] == "client_secret" {
			return allOrNone(upstream, entraLoginHost)
		}
	case "oauth":
		return allOrNone(upstream, t.Auth.OAuth.TokenURL)
	case "gcp_service_account":
		return allOrNone(upstream, googleTokenHost)
	}
	return allOrNone(upstream)
}

// mcpHosts returns where the credential at path of an MCP target is sent: its
// URL, and for a client secret the token endpoint as well.
func mcpHosts(t *registry.MCPTarget, path []string) []string {
	if len(path) == 3 && path[1] == "auth" && path[2] == "client_secret" && t.Auth != nil {
		return allOrNone(t.URL, t.Auth.TokenURL)
	}
	return allOrNone(t.URL)
}

// a2aHosts returns where the credential at path of an A2A target is sent:
// the agent's endpoint; the card URL when its auth also reads the card; the
// token endpoint for a client secret; the cloud's identity provider for a
// cloud credential.
func a2aHosts(t *registry.A2ATarget, path []string) []string {
	endpoint := t.Endpoint()
	if len(path) < 2 {
		return nil
	}
	switch path[1] {
	case "cloud_auth":
		if len(path) < 3 {
			return nil
		}
		switch path[2] {
		case "aws":
			hosts := []string{endpoint}
			if c := t.CloudAuth; c != nil && c.AWS != nil && c.AWS.UseRole && t.AWSRegion() != "" {
				hosts = append(hosts, "sts."+t.AWSRegion()+".amazonaws.com")
			}
			return allOrNone(hosts...)
		case "azure":
			return allOrNone(endpoint, entraLoginHost)
		case "gcp":
			return allOrNone(endpoint, googleTokenHost)
		}
		return nil
	case "auth":
		hosts := []string{endpoint}
		if t.Provider == registry.A2AProviderGeneric && t.CardAuth == registry.A2ACardAuthSame {
			hosts = append(hosts, t.CardURL)
		}
		if len(path) == 3 && path[2] == "client_secret" && t.Auth != nil {
			hosts = append(hosts, t.Auth.TokenURL)
		}
		return allOrNone(hosts...)
	}
	return allOrNone(endpoint)
}

// registryHosts returns where the credential at path of r is sent, or nil
// when that cannot be told.
func registryHosts(r *registry.Registry, path []string) []string {
	switch {
	case len(path) == 0:
		return nil
	case path[0] == "llm_target" && r.LLMTarget != nil:
		return llmHosts(r.LLMTarget, path)
	case path[0] == "mcp_target" && r.MCPTarget != nil:
		return mcpHosts(r.MCPTarget, path)
	case path[0] == "a2a_target" && r.A2ATarget != nil:
		return a2aHosts(r.A2ATarget, path)
	}
	return nil
}
