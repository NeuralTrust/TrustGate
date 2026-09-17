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

package context

import (
	"net/url"
	"strings"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// Metadata keys the MCP tools/call path sets on RequestContext once the tool
// has been bound to its upstream. Body.name stays the exposed (possibly
// federated) name; these describe the native binding for plugins that only
// read metadata, and for telemetry. They are advisory: the executor merges
// metadata back out of isolated requests, so a plugin can overwrite them. A
// plugin that gates the call must read RequestContext.MCPTool instead.
const (
	// MetadataMCPTool is the upstream-native tool name.
	MetadataMCPTool = "mcp.tool"
	// MetadataMCPRegistryID is the id of the registry that owns the tool.
	MetadataMCPRegistryID = "mcp.registry_id"
	// MetadataMCPRegistryName is the display name of the registry that owns the tool.
	MetadataMCPRegistryName = "mcp.registry_name"
	// MetadataMCPExposedTool is the name the caller used, as listed by tools/list.
	MetadataMCPExposedTool = "mcp.exposed_tool"
)

type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

type RoutingDecision struct {
	TierApplied bool
}

type RequestContext struct {
	GatewayID          string
	ConsumerID         string
	ConsumerType       string
	RegistryID         string
	RegistryPricing    *domain.Pricing
	Headers            map[string][]string
	Method             string
	Path               string
	Query              url.Values
	Body               []byte
	Messages           []string
	Attachments        []Attachment
	Metadata           map[string]interface{}
	ProcessAt          *time.Time
	IP                 string
	SessionID          string
	PreviousResponseID string
	Provider           string
	SourceFormat       string
	TargetFormat       string
	ProxyCapability    string
	AllowedModels      []string
	DefaultModel       string
	RequestedModel     string
	RoutingDecision    *RoutingDecision
	// MCP marks a native MCP tools/call payload so protocol-aware plugins
	// inspect it via the MCP text path instead of the LLM canonical decoders.
	MCP bool
	// MCPTool is the upstream-native tool name a resolved tools/call is bound
	// to, "" on any other request. A plugin deciding whether to allow the call
	// must read it here and not from MetadataMCPTool: Metadata is a channel
	// plugins write to and the executor merges back, so an earlier plugin in
	// the chain could name a different tool there. Scalar fields are never
	// merged out of an isolated request, so this one is the binding the
	// dispatcher fixed.
	MCPTool string
}

// HeaderValue returns the first non-empty value of the named header, matched
// case-insensitively. It returns "" when the header is absent or empty.
func (r *RequestContext) HeaderValue(name string) string {
	if r == nil || name == "" || len(r.Headers) == 0 {
		return ""
	}
	if values, ok := r.Headers[name]; ok && len(values) > 0 && values[0] != "" {
		return values[0]
	}
	for headerName, values := range r.Headers {
		if strings.EqualFold(headerName, name) && len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}
	return ""
}
