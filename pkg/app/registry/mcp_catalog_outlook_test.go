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
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

const (
	outlookCode        = "com.microsoft/outlook"
	outlookTemplate    = "https://agent365.svc.cloud.microsoft/agents/tenants/{tenantId}/servers/mcp_MailTools"
	agentToolsAppIDURI = "api://ea9ffc3e-8a23-4a7d-836d-234d7c7565c1"
)

// Saving an Outlook instance stores the Agent Tools app id URI as the resource,
// not the tenant-scoped MCP URL, and keeps the tenant in the Entra authority.
// It applies to a new install and to a re-save of a row stored with the
// /organizations authority, which only a re-save moves to the tenant.
func TestCanonicalizeMCPAuthFromCatalog_OutlookStoresAgentToolsResource(t *testing.T) {
	t.Parallel()
	cat, err := appcatalog.NewMCPServerCatalog(nil)
	require.NoError(t, err)

	for name, stored := range map[string]*domain.MCPAuth{
		"new install": {
			Mode:         domain.MCPAuthModeForwarded,
			Registration: domain.RegistrationManual,
			ClientID:     "cid",
			ClientSecret: "secret",
		},
		"saved before the catalog fix": {
			Mode:         domain.MCPAuthModeForwarded,
			Provider:     outlookCode,
			Registration: domain.RegistrationManual,
			ClientID:     "cid",
			AuthorizeURL: "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
			TokenURL:     "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
			Resource:     outlookTemplate,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			target := &domain.MCPTarget{
				Code:         outlookCode,
				URL:          outlookTemplate,
				URLVariables: []domain.MCPURLVariable{{Name: "tenantId", Required: true}},
				Auth:         stored,
			}
			require.NoError(t, appregistry.CanonicalizeMCPAuthFromCatalog(target, cat))
			require.Equal(t, agentToolsAppIDURI, target.Auth.Resource)
			require.False(t, target.Auth.ResourcePerInstance)
			require.Equal(t, "https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize", target.Auth.AuthorizeURL)
			require.Equal(t, "https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", target.Auth.TokenURL)
			require.False(t, target.PinsURLVariable("tenantId"))
			require.NoError(t, target.Validate())
		})
	}
}
