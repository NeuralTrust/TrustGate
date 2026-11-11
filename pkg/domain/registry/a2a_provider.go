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
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common/gcpkey"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

// A2AProvider says where an A2A agent is hosted, which decides how it is
// located and how the gateway signs in to it.
type A2AProvider string

const (
	A2AProviderGeneric           A2AProvider = "generic"
	A2AProviderBedrockAgentCore  A2AProvider = "bedrock_agentcore"
	A2AProviderAzureFoundry      A2AProvider = "azure_foundry"
	A2AProviderVertexAgentEngine A2AProvider = "vertex_agent_engine"
)

const (
	foundryHostSuffix         = ".services.ai.azure.com"
	foundryOBOScope           = "https://ai.azure.com/.default"
	agentCoreDefaultQualifier = "DEFAULT"
)

var (
	agentCoreARN     = regexp.MustCompile(`^arn:aws:bedrock-agentcore:([a-z]{2}(?:-[a-z]+)+-[0-9]+):[0-9]{12}:runtime/[A-Za-z0-9_-]+$`)
	agentCoreQual    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	foundryAgentName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	vertexProject    = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	vertexLocation   = regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)
	vertexEngineID   = regexp.MustCompile(`^[0-9]+$`)
)

type a2aLocator interface {
	validate() error
	cardURL(v A2AProtocolVersion) string
	endpoint() string
}

// AgentCoreLocator names an Amazon Bedrock AgentCore runtime.
type AgentCoreLocator struct {
	RuntimeARN string `json:"runtime_arn"`
	Qualifier  string `json:"qualifier,omitempty"`
}

// Region returns the AWS region of the runtime ARN, or "" when it is malformed.
func (l *AgentCoreLocator) Region() string {
	m := agentCoreARN.FindStringSubmatch(l.RuntimeARN)
	if m == nil {
		return ""
	}
	return m[1]
}

func (l *AgentCoreLocator) validate() error {
	if l.Region() == "" {
		return fmt.Errorf("%w: bedrock_agentcore.runtime_arn must be arn:aws:bedrock-agentcore:{region}:{account}:runtime/{id}", ErrInvalidRegistry)
	}
	if !agentCoreQual.MatchString(l.Qualifier) {
		return fmt.Errorf("%w: bedrock_agentcore.qualifier is not a valid qualifier", ErrInvalidRegistry)
	}
	return nil
}

func (l *AgentCoreLocator) base() string {
	return "https://bedrock-agentcore." + l.Region() + ".amazonaws.com/runtimes/" + url.QueryEscape(l.RuntimeARN) + "/invocations"
}

func (l *AgentCoreLocator) cardURL(A2AProtocolVersion) string {
	return l.base() + "/.well-known/agent-card.json?qualifier=" + url.QueryEscape(l.Qualifier)
}

func (l *AgentCoreLocator) endpoint() string {
	return l.base() + "/?qualifier=" + url.QueryEscape(l.Qualifier)
}

// FoundryLocator names a Microsoft Foundry agent.
type FoundryLocator struct {
	ProjectEndpoint string `json:"project_endpoint"`
	AgentName       string `json:"agent_name"`
}

func (l *FoundryLocator) validate() error {
	u, err := url.Parse(l.ProjectEndpoint)
	host := ""
	if err == nil {
		host = strings.ToLower(u.Hostname())
	}
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!strings.HasSuffix(host, foundryHostSuffix) || len(host) == len(foundryHostSuffix) ||
		!strings.HasPrefix(u.Path, "/api/projects/") || strings.Trim(strings.TrimPrefix(u.Path, "/api/projects/"), "/") == "" {
		return fmt.Errorf("%w: a Microsoft Foundry agent lives under services.ai.azure.com: project_endpoint must be https://{account}.services.ai.azure.com/api/projects/{project}", ErrInvalidRegistry)
	}
	if !foundryAgentName.MatchString(l.AgentName) {
		return fmt.Errorf("%w: azure_foundry.agent_name is required", ErrInvalidRegistry)
	}
	return nil
}

func (l *FoundryLocator) endpoint() string {
	return strings.TrimRight(l.ProjectEndpoint, "/") + "/agents/" + l.AgentName + "/endpoint/protocols/a2a"
}

func (l *FoundryLocator) cardURL(v A2AProtocolVersion) string {
	if v == "" {
		v = A2AVersion10
	}
	return l.endpoint() + "/agentCard/v" + string(v)
}

// VertexLocator names a Google Vertex AI Agent Engine.
type VertexLocator struct {
	Project           string `json:"project"`
	Location          string `json:"location"`
	ReasoningEngineID string `json:"reasoning_engine_id"`
}

func (l *VertexLocator) validate() error {
	if !vertexProject.MatchString(l.Project) || !vertexLocation.MatchString(l.Location) || !vertexEngineID.MatchString(l.ReasoningEngineID) {
		return fmt.Errorf("%w: vertex_agent_engine needs a valid project, location and numeric reasoning_engine_id", ErrInvalidRegistry)
	}
	return nil
}

func (l *VertexLocator) endpoint() string {
	return "https://" + l.Location + "-aiplatform.googleapis.com/v1beta1/projects/" + l.Project +
		"/locations/" + l.Location + "/reasoningEngines/" + l.ReasoningEngineID + "/a2a"
}

func (l *VertexLocator) cardURL(A2AProtocolVersion) string {
	return l.endpoint() + "/v1/card"
}

// A2ACloudAuth is the cloud credential of a hosted agent. Exactly one of its
// fields is set, the one its provider accepts.
type A2ACloudAuth struct {
	AWS   *A2AAWSAuth `json:"aws,omitempty"`
	Azure *AzureAuth  `json:"azure,omitempty"`
	GCP   *A2AGCPAuth `json:"gcp,omitempty"`
	// SecretUnreadable marks a credential read from storage whose secret could
	// not be decrypted and was returned empty. Never serialised.
	SecretUnreadable bool `json:"-"`
}

// A2AAWSAuth is AWSAuth plus the external id passed to sts:AssumeRole. Its
// region is ignored: the runtime ARN names it.
type A2AAWSAuth struct {
	AWSAuth
	ExternalID string `json:"external_id,omitempty"`
}

// A2AGCPAuth signs in with a service-account key, by impersonating a service
// account, or, with neither, with the pod's Application Default Credentials.
type A2AGCPAuth struct {
	ServiceAccountJSON        string `json:"service_account_json,omitempty"` // #nosec G117 -- upstream credential
	ImpersonateServiceAccount string `json:"impersonate_service_account,omitempty"`
}

func (c *A2ACloudAuth) kind() string {
	switch {
	case c.AWS != nil && c.Azure == nil && c.GCP == nil:
		return "aws"
	case c.Azure != nil && c.AWS == nil && c.GCP == nil:
		return "azure"
	case c.GCP != nil && c.AWS == nil && c.Azure == nil:
		return "gcp"
	default:
		return ""
	}
}

func (c *A2ACloudAuth) secretValues() []string {
	var v []string
	if c.AWS != nil {
		v = append(v, c.AWS.AccessKeyID, c.AWS.SecretAccessKey, c.AWS.SessionToken)
	}
	if c.Azure != nil {
		v = append(v, c.Azure.ClientSecret)
	}
	if c.GCP != nil {
		v = append(v, c.GCP.ServiceAccountJSON)
	}
	return v
}

func (c *A2ACloudAuth) validate() error {
	for _, v := range c.secretValues() {
		if secret.IsMasked(v) {
			return fmt.Errorf("%w: secret cannot be a masked value; omit the field to keep the stored value", ErrInvalidRegistry)
		}
	}
	switch {
	case c.AWS != nil:
		a := c.AWS
		keys := a.AccessKeyID != "" || a.SecretAccessKey != "" || a.SessionToken != ""
		if a.UseRole && keys {
			return fmt.Errorf("%w: cloud_auth.aws takes static keys or use_role, not both", ErrInvalidRegistry)
		}
		if a.UseRole && strings.TrimSpace(a.Role) == "" {
			return fmt.Errorf("%w: cloud_auth.aws.role is required when use_role is true", ErrInvalidRegistry)
		}
		if keys && (strings.TrimSpace(a.AccessKeyID) == "" || (a.SecretAccessKey == "" && !c.SecretUnreadable)) {
			return fmt.Errorf("%w: cloud_auth.aws static keys need access_key_id and secret_access_key", ErrInvalidRegistry)
		}
	case c.Azure != nil:
		a := c.Azure
		if a.APIKey != "" {
			return fmt.Errorf("%w: a Microsoft Foundry agent accepts only Microsoft Entra ID, not an api key", ErrInvalidRegistry)
		}
		sp := strings.TrimSpace(a.TenantID) != "" || strings.TrimSpace(a.ClientID) != "" || a.ClientSecret != ""
		complete := strings.TrimSpace(a.TenantID) != "" && strings.TrimSpace(a.ClientID) != "" &&
			(a.ClientSecret != "" || c.SecretUnreadable)
		if sp == a.UseManagedIdentity || (sp && !complete) {
			return fmt.Errorf("%w: cloud_auth.azure takes a service principal (tenant_id, client_id, client_secret) or use_managed_identity", ErrInvalidRegistry)
		}
	case c.GCP != nil:
		g := c.GCP
		if g.ServiceAccountJSON != "" && g.ImpersonateServiceAccount != "" {
			return fmt.Errorf("%w: cloud_auth.gcp takes service_account_json or impersonate_service_account, not both", ErrInvalidRegistry)
		}
		if g.ServiceAccountJSON != "" {
			if err := gcpkey.Validate(g.ServiceAccountJSON); err != nil {
				return fmt.Errorf("%w: cloud_auth.gcp.service_account_json: %s", ErrInvalidRegistry, err.Error())
			}
		}
		if g.ImpersonateServiceAccount != "" && !strings.Contains(g.ImpersonateServiceAccount, "@") {
			return fmt.Errorf("%w: cloud_auth.gcp.impersonate_service_account must be a service account email", ErrInvalidRegistry)
		}
	}
	return nil
}

func (c *A2ACloudAuth) resolveSecretsFrom(prev *A2ACloudAuth) {
	if c == nil || prev == nil || c.kind() != prev.kind() {
		return
	}
	switch c.kind() {
	case "aws":
		if c.AWS.UseRole != prev.AWS.UseRole {
			return
		}
		c.AWS.AccessKeyID = secret.Resolve(c.AWS.AccessKeyID, prev.AWS.AccessKeyID)
		c.AWS.SecretAccessKey = secret.Resolve(c.AWS.SecretAccessKey, prev.AWS.SecretAccessKey)
		c.AWS.SessionToken = secret.Resolve(c.AWS.SessionToken, prev.AWS.SessionToken)
		c.SecretUnreadable = c.AWS.SecretAccessKey == "" && prev.SecretUnreadable
	case "azure":
		if c.Azure.ClientID != prev.Azure.ClientID || c.Azure.TenantID != prev.Azure.TenantID {
			return
		}
		c.Azure.ClientSecret = secret.Resolve(c.Azure.ClientSecret, prev.Azure.ClientSecret)
		c.SecretUnreadable = c.Azure.ClientSecret == "" && prev.SecretUnreadable
	case "gcp":
		if c.GCP.ImpersonateServiceAccount != "" {
			return
		}
		c.GCP.ServiceAccountJSON = secret.Resolve(c.GCP.ServiceAccountJSON, prev.GCP.ServiceAccountJSON)
		c.SecretUnreadable = c.GCP.ServiceAccountJSON == "" && prev.SecretUnreadable
	}
}

func (p A2AProvider) cloudKind() string {
	switch p {
	case A2AProviderBedrockAgentCore:
		return "aws"
	case A2AProviderAzureFoundry:
		return "azure"
	case A2AProviderVertexAgentEngine:
		return "gcp"
	default:
		return ""
	}
}

func (p A2AProvider) allowsAuth(a *MCPAuth) bool {
	userToken := a.Mode == MCPAuthModeExchange && (a.Pattern == ExchangeOBO || a.Pattern == ExchangeTokenExchange)
	switch p {
	case A2AProviderGeneric:
		return a.Mode == MCPAuthModeNone || a.Mode == MCPAuthModeStatic || a.Mode == MCPAuthModeClientCredentials ||
			a.Mode == MCPAuthModeExchange
	case A2AProviderBedrockAgentCore:
		return a.Mode == A2AAuthModeCloud || a.Mode == MCPAuthModeClientCredentials || userToken
	case A2AProviderAzureFoundry:
		return a.Mode == A2AAuthModeCloud || (a.Mode == MCPAuthModeExchange && a.Pattern == ExchangeOBO)
	case A2AProviderVertexAgentEngine:
		return a.Mode == A2AAuthModeCloud
	default:
		return false
	}
}

func (p A2AProvider) authError() error {
	var reason string
	switch p {
	case A2AProviderGeneric:
		reason = "auth mode cloud is only valid for agents hosted on Amazon Bedrock AgentCore, Microsoft Foundry or Vertex AI"
	case A2AProviderBedrockAgentCore:
		reason = "an Amazon Bedrock AgentCore agent accepts auth mode cloud with cloud_auth.aws, client_credentials, " +
			"or exchange with obo or token_exchange; it cannot validate a token signed by TrustGate yet"
	case A2AProviderAzureFoundry:
		reason = "a Microsoft Foundry agent accepts only Microsoft Entra ID: auth mode cloud with cloud_auth.azure, or exchange with obo"
	default:
		reason = "a Vertex AI agent accepts only Google tokens of a service account: auth mode cloud with cloud_auth.gcp"
	}
	return fmt.Errorf("%w: %s", ErrInvalidRegistry, reason)
}

func (p A2AProvider) cloudError() error {
	var reason string
	switch p {
	case A2AProviderBedrockAgentCore:
		reason = "an Amazon Bedrock AgentCore agent signs in with AWS: set cloud_auth.aws"
	case A2AProviderAzureFoundry:
		reason = "a Microsoft Foundry agent requires Microsoft Entra ID, even to read its card: set cloud_auth.azure"
	case A2AProviderVertexAgentEngine:
		reason = "a Vertex AI agent requires a Google service account token, even to read its card: set cloud_auth.gcp"
	default:
		reason = "cloud_auth is only valid with auth mode cloud or card_auth cloud"
	}
	return fmt.Errorf("%w: %s", ErrInvalidRegistry, reason)
}

func (p A2AProvider) locatedBy() string {
	switch p {
	case A2AProviderBedrockAgentCore:
		return "an Amazon Bedrock AgentCore agent is located by bedrock_agentcore (runtime_arn, qualifier)"
	case A2AProviderAzureFoundry:
		return "a Microsoft Foundry agent is located by azure_foundry (project_endpoint, agent_name)"
	case A2AProviderVertexAgentEngine:
		return "a Vertex AI agent is located by vertex_agent_engine (project, location, reasoning_engine_id)"
	default:
		return "a generic agent is located by card_url"
	}
}
