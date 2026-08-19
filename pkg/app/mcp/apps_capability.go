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

// MCPAppsExtensionIdentifier is the SEP-1865 UI extension identifier.
const MCPAppsExtensionIdentifier = "io.modelcontextprotocol/ui"

// MCPAppsHTMLMIMEType is the SEP-1865 HTML resource MIME type.
const MCPAppsHTMLMIMEType = "text/html;profile=mcp-app"

// MCPAppsClientCapability is a normalized client UI declaration.
type MCPAppsClientCapability struct {
	MIMETypes []string
}

// ParseMCPAppsClientCapability parses a SEP-1865 UI extension settings object.
func ParseMCPAppsClientCapability(raw any) (MCPAppsClientCapability, bool) {
	settings, ok := raw.(map[string]any)
	if !ok || len(settings) != 1 {
		return MCPAppsClientCapability{}, false
	}
	mimeTypes, ok := settings["mimeTypes"].([]any)
	if !ok || len(mimeTypes) == 0 {
		return MCPAppsClientCapability{}, false
	}
	capability := MCPAppsClientCapability{}
	for _, value := range mimeTypes {
		mimeType, ok := value.(string)
		if !ok {
			return MCPAppsClientCapability{}, false
		}
		if mimeType == MCPAppsHTMLMIMEType {
			capability.MIMETypes = []string{MCPAppsHTMLMIMEType}
		}
	}
	return capability, len(capability.MIMETypes) == 1
}
