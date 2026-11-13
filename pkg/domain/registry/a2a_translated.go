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
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Agents the gateway reaches through their provider's own API rather than
// A2A: it translates each call, and builds their card itself, since they
// publish none.
const (
	A2AProviderAgentCoreHarness A2AProvider = "agentcore_harness"
	A2AProviderDatabricks       A2AProvider = "databricks_agent"
)

const (
	databricksAppsHostSuffix = "databricksapps.com"
	databricksScope          = "all-apis"
)

var (
	harnessARN         = regexp.MustCompile(`^arn:aws:bedrock-agentcore:([a-z]{2}(?:-[a-z]+)+-[0-9]+):[0-9]{12}:harness/([A-Za-z][A-Za-z0-9_]{0,39})-[A-Za-z0-9]{10}$`)
	databricksEndpoint = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)
)

// HarnessLocator names an Amazon Bedrock AgentCore harness: a managed agent
// called with InvokeHarness, not an A2A runtime.
type HarnessLocator struct {
	HarnessARN string `json:"harness_arn"`
	Qualifier  string `json:"qualifier,omitempty"`
}

// Region returns the AWS region of the harness ARN, or "" when it is malformed.
func (l *HarnessLocator) Region() string {
	if m := harnessARN.FindStringSubmatch(l.HarnessARN); m != nil {
		return m[1]
	}
	return ""
}

// Name is the harness's name: its ARN's id without the generated suffix.
func (l *HarnessLocator) Name() string {
	if m := harnessARN.FindStringSubmatch(l.HarnessARN); m != nil {
		return m[2]
	}
	return ""
}

func (l *HarnessLocator) validate() error {
	if l.Region() == "" {
		return fmt.Errorf("%w: agentcore_harness.harness_arn must be arn:aws:bedrock-agentcore:{region}:{account}:harness/{name}-{id}", ErrInvalidRegistry)
	}
	if !agentCoreQual.MatchString(l.Qualifier) {
		return fmt.Errorf("%w: agentcore_harness.qualifier is not a valid endpoint name", ErrInvalidRegistry)
	}
	return nil
}

func (l *HarnessLocator) endpoint() string {
	return "https://bedrock-agentcore." + l.Region() + ".amazonaws.com/harnesses/invoke?harnessArn=" +
		url.QueryEscape(l.HarnessARN) + "&qualifier=" + url.QueryEscape(l.Qualifier)
}

func (l *HarnessLocator) cardURL(A2AProtocolVersion) string { return "" }

// DatabricksLocator names a Databricks agent (a ResponsesAgent): a Model
// Serving endpoint of the workspace, or a Databricks App. The workspace is
// required either way: it issues the OAuth tokens an App accepts too.
type DatabricksLocator struct {
	WorkspaceURL    string `json:"workspace_url"`
	ServingEndpoint string `json:"serving_endpoint,omitempty"`
	AppURL          string `json:"app_url,omitempty"`
}

func (l *DatabricksLocator) validate() error {
	if !isOriginURL(l.WorkspaceURL) {
		return fmt.Errorf("%w: databricks_agent.workspace_url must be the workspace's https URL, e.g. https://adb-123.4.azuredatabricks.net", ErrInvalidRegistry)
	}
	switch {
	case (l.ServingEndpoint == "") == (l.AppURL == ""):
		return fmt.Errorf("%w: databricks_agent takes serving_endpoint (a Model Serving endpoint) or app_url (a Databricks App), one of them", ErrInvalidRegistry)
	case l.ServingEndpoint != "" && !databricksEndpoint.MatchString(l.ServingEndpoint):
		return fmt.Errorf("%w: databricks_agent.serving_endpoint is not a valid endpoint name", ErrInvalidRegistry)
	case l.AppURL != "" && (!isOriginURL(l.AppURL) || !strings.HasSuffix(strings.ToLower(hostOf(l.AppURL)), "."+databricksAppsHostSuffix)):
		return fmt.Errorf("%w: databricks_agent.app_url must be the App's https URL on %s", ErrInvalidRegistry, databricksAppsHostSuffix)
	}
	return nil
}

func (l *DatabricksLocator) endpoint() string {
	if l.AppURL != "" {
		return strings.TrimRight(l.AppURL, "/") + "/responses"
	}
	return strings.TrimRight(l.WorkspaceURL, "/") + "/serving-endpoints/" + l.ServingEndpoint + "/invocations"
}

func (l *DatabricksLocator) cardURL(A2AProtocolVersion) string { return "" }

// Name is the agent's name: its serving endpoint, else its App's.
func (l *DatabricksLocator) Name() string {
	if l.ServingEndpoint != "" {
		return l.ServingEndpoint
	}
	name, _, _ := strings.Cut(hostOf(l.AppURL), ".")
	return name
}

// TokenURL is the workspace's OAuth token endpoint, which issues the
// machine-to-machine tokens of a service principal.
func (l *DatabricksLocator) TokenURL() string {
	return strings.TrimRight(l.WorkspaceURL, "/") + "/oidc/v1/token"
}

// isOriginURL reports whether s is an https URL with a host and nothing after it but "/".
func isOriginURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil &&
		(u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == ""
}

// BuildsCard reports whether the gateway builds the agent's card itself: the
// agent publishes none, because it is reached through its provider's API.
func (p A2AProvider) BuildsCard() bool {
	return p == A2AProviderAgentCoreHarness || p == A2AProviderDatabricks
}

// BuiltCard is the card the gateway publishes for an agent that has none: its
// name, a chat skill, A2A 0.3 over JSON-RPC at the gateway, with streaming.
func (t *A2ATarget) BuiltCard() []byte {
	name, host := "", ""
	switch {
	case t.AgentCoreHarness != nil:
		name, host = t.AgentCoreHarness.Name(), "an Amazon Bedrock AgentCore harness"
	case t.Databricks != nil:
		name, host = t.Databricks.Name(), "a Databricks agent"
	}
	card := map[string]any{
		"name":               name,
		"description":        "Reached through TrustGate, which calls " + host + " for each message.",
		"url":                t.Endpoint(),
		"version":            "1.0.0",
		"protocolVersion":    "0.3.0",
		"preferredTransport": "JSONRPC",
		"capabilities":       map[string]any{"streaming": true},
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"skills": []map[string]any{{
			"id":          "chat",
			"name":        "Chat",
			"description": "Send a message and get the agent's answer. The conversation continues in the same context.",
			"tags":        []string{"chat"},
		}},
	}
	out, _ := json.Marshal(card)
	return out
}
