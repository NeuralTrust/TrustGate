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

package request

import (
	"encoding/json"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

// Whose account an instance uses is the difference between two instances of one
// server, so it has to survive the wire. A field the request struct does not
// name is dropped silently, and the instance is saved as everyone's own.
func TestCreateRegistryRequest_CarriesTheUpstreamAccount(t *testing.T) {
	var req CreateRegistryRequest
	body := `{
		"name": "Notion (shared)",
		"type": "MCP",
		"mcp_target": {
			"url": "https://mcp.notion.com/mcp",
			"code": "com.notion/mcp",
			"transport": "streamable-http",
			"auth": {"mode": "forwarded", "provider": "com.notion/mcp", "account": "shared", "registration": "auto"}
		}
	}`
	require.NoError(t, json.Unmarshal([]byte(body), &req))

	target := req.ToMCPTarget()

	require.NotNil(t, target)
	require.NotNil(t, target.Auth)
	require.Equal(t, domain.MCPAccountShared, target.Auth.Account)
	require.True(t, target.Auth.Shared())
}

// Omitted is the caller's own account, which is what every instance was before
// shared accounts existed.
func TestCreateRegistryRequest_NoAccountIsTheCallersOwn(t *testing.T) {
	var req CreateRegistryRequest
	body := `{
		"name": "Notion",
		"type": "MCP",
		"mcp_target": {
			"url": "https://mcp.notion.com/mcp",
			"transport": "streamable-http",
			"auth": {"mode": "forwarded", "provider": "com.notion/mcp", "registration": "auto"}
		}
	}`
	require.NoError(t, json.Unmarshal([]byte(body), &req))

	target := req.ToMCPTarget()

	require.NotNil(t, target.Auth)
	require.Empty(t, string(target.Auth.Account))
	require.False(t, target.Auth.Shared())
}
