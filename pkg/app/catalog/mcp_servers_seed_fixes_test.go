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

package catalog

import (
	"strings"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

// TestCuratedCatalog_SeedFixes locks the catalog corrections from the
// 2026-10-18 seed pass: URLs, auth models, region options, and scopes.
// Each assertion is the value that was wrong before that pass.
func TestCuratedCatalog_SeedFixes(t *testing.T) {
	t.Parallel()
	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	t.Run("excalidraw and globalping", func(t *testing.T) {
		excalidraw := mustCatalogServer(t, cat, "com.excalidraw/mcp")
		require.Equal(t, "https://mcp.excalidraw.com/mcp", excalidraw.URL)
		require.Equal(t, authHintNone, excalidraw.AuthHint)
		require.True(t, excalidraw.SelfService)

		globalping := mustCatalogServer(t, cat, "io.globalping/mcp")
		require.Equal(t, "https://mcp.globalping.dev/mcp", globalping.URL)
		require.True(t, globalping.RequiresAuth)
		require.True(t, globalping.SelfService)
		require.Equal(t, authHintOAuth, globalping.AuthHint)
		require.False(t, globalping.RequiresConfig)
		requireOAuth(t, globalping, "auto", true, []string{"measurements"})
		require.Equal(t, "https://mcp.globalping.dev/authorize", globalping.OAuth.AuthorizeURL)
		require.Equal(t, "https://mcp.globalping.dev/token", globalping.OAuth.TokenURL)
		require.Equal(t, "https://mcp.globalping.dev/mcp", globalping.OAuth.Resource)
	})

	t.Run("shopify shop hint", func(t *testing.T) {
		shopify := mustCatalogServer(t, cat, "com.shopify/storefront")
		require.Equal(t, "https://{shop}.myshopify.com/api/mcp", shopify.URL)
		require.Equal(t, "Store subdomain, e.g. example (without .myshopify.com).", variableByName(t, shopify, "shop").Description)
		require.Equal(t, "https://allbirds.myshopify.com/api/mcp", resolveCatalogURL(t, shopify, map[string]string{"shop": "allbirds"}))
	})

	t.Run("manual oauth apps", func(t *testing.T) {
		for _, code := range []string{
			"com.vercel/mcp",
			"com.intercom/mcp",
			"com.squareup/mcp",
			"com.checkr/mcp",
			"com.shortcut/mcp",
			"io.prismic/mcp",
			"com.semrush/mcp",
			"app.thoughtspot/mcp",
		} {
			server := mustCatalogServer(t, cat, code)
			require.False(t, server.SelfService, code)
			require.True(t, server.RequiresConfig, code)
			requireOAuth(t, server, "manual", false, nil)
			require.NotNil(t, server.ConfigGuide, code)
			require.Contains(t, server.ConfigGuide.Note, "https://<gateway-mcp host>/oauth/callback/"+code)
			require.Contains(t, server.ConfigGuide.Steps[1], "https://<gateway-mcp host>/oauth/callback/"+code)
		}

		aws := mustCatalogServer(t, cat, "com.amazon.aws/mcp")
		require.False(t, aws.SelfService)
		requireOAuth(t, aws, "manual", false, nil)
		require.Contains(t, aws.ConfigGuide.Note, "https://<gateway-mcp host>/oauth/callback/com.amazon.aws/mcp")
		require.Contains(t, aws.ConfigGuide.Steps[0], "AWSMCPSignInOAuthAccessPolicy")
		require.Equal(t, "https://docs.aws.amazon.com/signin/latest/userguide/aws-mcp-server.html", aws.ConfigGuide.DocsURL)
	})

	t.Run("firecrawl api key", func(t *testing.T) {
		firecrawl := mustCatalogServer(t, cat, "dev.firecrawl/mcp")
		require.Equal(t, "https://mcp.firecrawl.dev/v2/mcp", firecrawl.URL)
		require.Nil(t, firecrawl.OAuth)
		require.False(t, firecrawl.SelfService)
		require.Equal(t, authHintStatic, firecrawl.AuthHint)
		require.Equal(t, "Bearer", firecrawl.AuthHeaders[0].Scheme)
		require.True(t, firecrawl.AuthHeaders[0].Required)
		require.Contains(t, firecrawl.Description, "keyless access is a separate limited endpoint")
	})

	t.Run("trailing slash urls", func(t *testing.T) {
		mem0 := mustCatalogServer(t, cat, "ai.mem0/mcp")
		require.Equal(t, "https://mcp.mem0.ai/mcp/", mem0.URL)
		require.Equal(t, "Token", mem0.AuthHeaders[0].Scheme)
		require.Contains(t, mem0.AuthHeaders[0].Description, "(we add 'Token')")

		scrapingant := mustCatalogServer(t, cat, "com.scrapingant/mcp")
		require.Equal(t, "https://api.scrapingant.com/mcp/", scrapingant.URL)
		require.True(t, strings.HasPrefix(scrapingant.URL, "https://"))
		require.Equal(t, "raw", scrapingant.AuthHeaders[0].Scheme)
		require.Equal(t, "x-api-key", scrapingant.AuthHeaders[0].Name)

		plaid := mustCatalogServer(t, cat, "com.plaid/mcp")
		require.Equal(t, "https://api.dashboard.plaid.com/mcp/", plaid.URL)
		require.Equal(t, "https://api.dashboard.plaid.com/mcp/", plaid.OAuth.Resource)
		require.Empty(t, plaid.AuthHeaders)
		require.True(t, plaid.SelfService)
		require.False(t, plaid.RequiresConfig)
		requireOAuth(t, plaid, "auto", true, []string{"mcp:dashboard"})
		require.Equal(t, "https://dashboard.plaid.com/oauth/authorize", plaid.OAuth.AuthorizeURL)
		require.Equal(t, "https://api.dashboard.plaid.com/oauth/token", plaid.OAuth.TokenURL)
	})

	t.Run("advertised scopes", func(t *testing.T) {
		cases := []struct {
			code   string
			scopes []string
		}{
			{"dev.jam/mcp", []string{"mcp:read", "mcp:write"}},
			{"com.motherduck/mcp", []string{"mcp:connect"}},
			{"net.todoist/mcp", []string{"data:read_write"}},
			{"com.clickhouse/cloud-mcp", []string{"mcp:access", "openid", "profile", "email"}},
			{"com.railway/mcp", []string{"workspace:member", "offline_access"}},
			{"com.amplitude/mcp", []string{"all:read", "offline_access"}},
			{"com.pandadoc/mcp", []string{"read", "documents:read"}},
			{"com.pagerduty/mcp", []string{"read", "incidents.read", "oncalls.read", "services.read", "users.read", "openid"}},
		}
		for _, tc := range cases {
			server := mustCatalogServer(t, cat, tc.code)
			require.Equal(t, tc.scopes, server.OAuth.Scopes, tc.code)
			require.NotContains(t, server.OAuth.Scopes, "read+write", tc.code)
			require.NotContains(t, server.OAuth.Scopes, "write", tc.code)
		}
	})

	t.Run("new relic regions", func(t *testing.T) {
		nr := mustCatalogServer(t, cat, "com.newrelic/mcp")
		require.Equal(t, "https://{host}/mcp/", nr.URL)
		require.Equal(t, []string{"mcp.newrelic.com", "mcp.eu.newrelic.com"}, optionValues(variableByName(t, nr, "host")))
		require.Equal(t, []string{"observability:read", "offline", "offline_access"}, nr.OAuth.Scopes)
		require.Empty(t, nr.OAuth.Resource)
		require.True(t, nr.OAuth.ResourceMetadata)
		require.Equal(t, "https://oauth2.service.newrelic.com/oauth2/auth", nr.OAuth.AuthorizeURL)
		require.Equal(t, "https://oauth2.service.newrelic.com/oauth2/token", nr.OAuth.TokenURL)
		require.Equal(t, "https://mcp.newrelic.com/mcp/", resolveCatalogURL(t, nr, map[string]string{"host": "mcp.newrelic.com"}))
		require.Equal(t, "https://mcp.eu.newrelic.com/mcp/", resolveCatalogURL(t, nr, map[string]string{"host": "mcp.eu.newrelic.com"}))
	})

	t.Run("pagerduty region", func(t *testing.T) {
		pagerduty := mustCatalogServer(t, cat, "com.pagerduty/mcp")
		require.Equal(t, "https://{host}/mcp", pagerduty.URL)
		host := variableByName(t, pagerduty, "host")
		require.True(t, host.Required)
		require.Equal(t, "PagerDuty service region.", host.Description)
		require.Equal(t, []string{"mcp.pagerduty.com", "mcp.eu.pagerduty.com"}, optionValues(host))
		require.Equal(t, "United States", host.Options[0].Label)
		require.Equal(t, "Europe", host.Options[1].Label)
		require.Equal(t, "manual", pagerduty.OAuth.Registration)
		require.NotNil(t, pagerduty.OAuth.DCR)
		require.False(t, *pagerduty.OAuth.DCR)
		require.NotNil(t, pagerduty.OAuth.PKCE)
		require.True(t, *pagerduty.OAuth.PKCE)
		require.Equal(t, "https://{host}/mcp", pagerduty.OAuth.Resource)
		require.Equal(t, "https://app.pagerduty.com/global/oauth/authorize", pagerduty.OAuth.AuthorizeURL)
		require.Equal(t, "https://app.pagerduty.com/global/oauth/token", pagerduty.OAuth.TokenURL)
		require.Equal(t, []string{
			"read", "incidents.read", "oncalls.read", "services.read", "users.read", "openid",
		}, pagerduty.OAuth.Scopes)
		require.NotContains(t, pagerduty.OAuth.Scopes, "write")
		require.Equal(t, "https://mcp.pagerduty.com/mcp",
			resolveCatalogURL(t, pagerduty, map[string]string{"host": "mcp.pagerduty.com"}))
		require.Equal(t, "https://mcp.eu.pagerduty.com/mcp",
			resolveCatalogURL(t, pagerduty, map[string]string{"host": "mcp.eu.pagerduty.com"}))
	})

	t.Run("algolia optional key", func(t *testing.T) {
		algolia := mustCatalogServer(t, cat, "com.algolia/mcp")
		require.False(t, algolia.RequiresAuth)
		require.True(t, algolia.SelfService)
		require.Equal(t, authHintStatic, algolia.AuthHint)
		require.Len(t, algolia.URLVariables, 2)
		header := algolia.AuthHeaders[0]
		require.Equal(t, "Authorization", header.Name)
		require.False(t, header.Required)
		require.Equal(t, "Bearer", header.Scheme)
		require.Equal(t, "Optional; the public Algolia MCP endpoint doesn't require it.", header.Description)
	})

	t.Run("regional and environment hosts", func(t *testing.T) {
		langfuse := mustCatalogServer(t, cat, "com.langfuse/mcp")
		require.Equal(t, "https://{host}/api/public/mcp", langfuse.URL)
		require.Equal(t, []string{
			"cloud.langfuse.com",
			"us.cloud.langfuse.com",
			"jp.cloud.langfuse.com",
			"hipaa.cloud.langfuse.com",
		}, optionValues(variableByName(t, langfuse, "host")))
		require.Contains(t, langfuse.AuthHeaders[0].Description, "Project keys are read/write")
		require.Contains(t, langfuse.AuthHeaders[0].Description, "(we add 'Basic')")
		require.Equal(t, "https://us.cloud.langfuse.com/api/public/mcp",
			resolveCatalogURL(t, langfuse, map[string]string{"host": "us.cloud.langfuse.com"}))

		jumpcloud := mustCatalogServer(t, cat, "com.jumpcloud/genai")
		require.Equal(t, "https://{host}/v1", jumpcloud.URL)
		require.Equal(t, []string{"mcp.jumpcloud.com", "mcp.eu.jumpcloud.com", "mcp.in.jumpcloud.com"},
			optionValues(variableByName(t, jumpcloud, "host")))
		require.Contains(t, jumpcloud.AuthHeaders[0].Description, "jca_")
		require.Contains(t, jumpcloud.AuthHeaders[0].Description, "read-only admin")
		require.Equal(t, "https://mcp.eu.jumpcloud.com/v1",
			resolveCatalogURL(t, jumpcloud, map[string]string{"host": "mcp.eu.jumpcloud.com"}))

		paddle := mustCatalogServer(t, cat, "com.paddle/mcp")
		require.Equal(t, "https://{host}/mcp", paddle.URL)
		require.Equal(t, []string{"mcp.paddle.com", "sandbox-mcp.paddle.com"}, optionValues(variableByName(t, paddle, "host")))
		require.Contains(t, paddle.AuthHeaders[0].Description, "never a live billing key")
		require.Equal(t, "https://sandbox-mcp.paddle.com/mcp",
			resolveCatalogURL(t, paddle, map[string]string{"host": "sandbox-mcp.paddle.com"}))

		elastic := mustCatalogServer(t, cat, "co.elastic/agent-builder-mcp")
		require.Equal(t, "https://{kibana_url}/s/{space}/api/agent_builder/mcp", elastic.URL)
		require.Equal(t, "Kibana endpoint host (…kb….cloud.es.io).", variableByName(t, elastic, "kibana_url").Description)
		require.Equal(t, "Kibana space id. The default space is default.", variableByName(t, elastic, "space").Description)
		require.Contains(t, elastic.AuthHeaders[0].Description, "role_descriptors")
		require.Contains(t, elastic.Description, "depends on the deployment")
		require.Equal(t,
			"https://acme.kb.eu-west-1.aws.cloud.es.io/s/default/api/agent_builder/mcp",
			resolveCatalogURL(t, elastic, map[string]string{
				"kibana_url": "acme.kb.eu-west-1.aws.cloud.es.io",
				"space":      "default",
			}))

		workato := mustCatalogServer(t, cat, "com.workato/developer-api")
		require.Equal(t, "https://{host}/mcp", workato.URL)
		require.Equal(t, []string{
			"app.workato.com",
			"app.eu.workato.com",
			"app.jp.workato.com",
			"app.sg.workato.com",
			"app.au.workato.com",
			"app.il.workato.com",
			"app.kr.workato.com",
			"app.uk.workato.com",
			"app.trial.workato.com",
		}, optionValues(variableByName(t, workato, "host")))
		require.Contains(t, workato.Description, "API client role")
		require.Equal(t, "https://app.trial.workato.com/mcp",
			resolveCatalogURL(t, workato, map[string]string{"host": "app.trial.workato.com"}))
	})

	t.Run("teamwork plaid cube chargebee", func(t *testing.T) {
		teamwork := mustCatalogServer(t, cat, "com.teamwork/mcp")
		require.Empty(t, teamwork.AuthHeaders)
		require.True(t, teamwork.SelfService)
		require.Contains(t, teamwork.Description, "Settings > AI")
		requireOAuth(t, teamwork, "auto", true, []string{"projects"})
		require.Equal(t, "https://www.teamwork.com/launchpad/login", teamwork.OAuth.AuthorizeURL)
		require.Equal(t, "https://www.teamwork.com/launchpad/v1/token.json", teamwork.OAuth.TokenURL)
		require.Equal(t, "https://mcp.ai.teamwork.com", teamwork.OAuth.Resource)
		require.Len(t, teamwork.Tools, 180)

		cube := mustCatalogServer(t, cat, "dev.cube/mcp")
		require.Equal(t, "https://cubecloud.dev/mcp", cube.URL)
		require.Empty(t, cube.URLVariables)
		require.True(t, cube.SelfService)
		require.False(t, cube.RequiresConfig)
		requireOAuth(t, cube, "auto", true, []string{"mcp-agent-access"})
		require.Equal(t, "https://cubecloud.dev/mcp/oauth/authorize", cube.OAuth.AuthorizeURL)
		require.Equal(t, "https://cubecloud.dev/mcp/oauth/token", cube.OAuth.TokenURL)
		require.Equal(t, "https://cubecloud.dev/mcp", resolveCatalogURL(t, cube, nil))

		chargebee := mustCatalogServer(t, cat, "com.chargebee/mcp")
		require.Equal(t, "https://{subdomain}.{region}.chargebee.com/{agent}", chargebee.URL)
		require.Nil(t, chargebee.OAuth)
		require.False(t, chargebee.SelfService)
		require.True(t, chargebee.RequiresAuth)
		require.False(t, chargebee.AuthHeaders[0].Required)
		require.Equal(t, "Bearer", chargebee.AuthHeaders[0].Scheme)
		require.Contains(t, chargebee.AuthHeaders[0].Description, "Settings > Agentic AI > MCP Servers")
		require.Equal(t, []string{"mcp", "mcp.eu", "mcp.au"}, optionValues(variableByName(t, chargebee, "region")))
		require.Equal(t, []string{"knowledge_base_agent", "data_lookup_agent", "onboarding_agent"},
			optionValues(variableByName(t, chargebee, "agent")))
		require.Equal(t,
			"https://acme.mcp.eu.chargebee.com/data_lookup_agent",
			resolveCatalogURL(t, chargebee, map[string]string{
				"subdomain": "acme",
				"region":    "mcp.eu",
				"agent":     "data_lookup_agent",
			}))
		require.Equal(t, []string{"chargebee_documentation_search", "chargebee_code_planner"}, toolNames(chargebee))
	})

	t.Run("pipedream client credentials", func(t *testing.T) {
		pipedream := mustCatalogServer(t, cat, "com.pipedream/mcp")
		require.False(t, pipedream.SelfService)
		require.Equal(t, authHintOAuth, pipedream.AuthHint)
		require.Equal(t, "client_credentials", pipedream.OAuth.GrantType)
		require.Equal(t, "https://api.pipedream.com/v1/oauth/token", pipedream.OAuth.TokenURL)
		require.Equal(t, "client_secret_post", pipedream.OAuth.TokenEndpointAuthMethod)
		require.Equal(t, []string{"x-pd-project-id", "x-pd-environment", "x-pd-external-user-id", "x-pd-app-slug"}, headerNames(pipedream))
		for _, header := range pipedream.AuthHeaders {
			require.NotEqual(t, "Authorization", header.Name)
		}
		require.Equal(t, "https://pipedream.com/docs/connect/mcp/developers", pipedream.ConfigGuide.DocsURL)
	})

	t.Run("dropbox and jotform dcr", func(t *testing.T) {
		dropbox := mustCatalogServer(t, cat, "com.dropbox/mcp")
		require.True(t, dropbox.SelfService)
		require.False(t, dropbox.RequiresConfig)
		requireOAuth(t, dropbox, "auto", true, []string{
			"account_info.read",
			"file_requests.read",
			"file_requests.write",
			"files.content.read",
			"files.content.write",
			"files.metadata.read",
			"sharing.read",
			"sharing.write",
		})

		jotform := mustCatalogServer(t, cat, "com.jotform/mcp")
		require.Equal(t, "https://mcp.jotform.com/mcp", jotform.URL)
		require.Equal(t, "https://mcp.jotform.com/mcp", resolveCatalogURL(t, jotform, nil))
		require.True(t, jotform.SelfService)
		requireOAuth(t, jotform, "auto", true, []string{"readOnly"})
	})
}

// TestCuratedCatalog_SeedFixesLeaveUnchangedEntries locks the entries this
// pass deliberately did not rewrite: Zoom scopes, Vanta's existing region
// options, AssemblyAI's docs URL, and Halo's static token.
func TestCuratedCatalog_SeedFixesLeaveUnchangedEntries(t *testing.T) {
	t.Parallel()
	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	zoom := map[string][]string{
		"us.zoom/docs": {
			"docs:write:import", "docs:read:export",
		},
		"us.zoom/revenue-accelerator": {
			"zra:read:team", "zra:read:conversations", "zra:read:list_deals", "zra:read:deal",
			"iq_conversation:read", "iq_deal:read", "iq_comment:read", "iq_coaching:read",
		},
		"us.zoom/team-chat": {
			"chat_channel:read", "chat_channel:write", "team_chat:read:channel",
			"team_chat:read:list_user_channels", "team_chat:read:list_user_messages",
			"team_chat:write:user_message", "team_chat:read:list_members",
		},
		"us.zoom/whiteboard": {
			"whiteboard:read:whiteboard", "whiteboard:write:whiteboard", "whiteboard:read:list_whiteboards",
			"whiteboard:write:collaborator", "whiteboard:update:collaborator", "whiteboard:delete:collaborator",
			"whiteboard:read:list_collaborators",
		},
		"us.zoom/workspace": {
			"meeting:read:search", "meeting:read:assets", "cloud_recording:read:content",
			"cloud_recording:read:list_user_recordings", "docs:read:export", "docs:write:import",
			"ai_companion:read:search",
		},
	}
	for code, scopes := range zoom {
		server := mustCatalogServer(t, cat, code)
		require.Equal(t, scopes, server.OAuth.Scopes, code)
	}

	// ENG-2237: Zoom keeps one token per OAuth app. The four servers an admin
	// installs side by side say so in the setup note. Scopes stay as seeded.
	const zoomAppHint = "Zoom keeps only the latest token per OAuth app, so each Zoom server needs its own Zoom app (client ID). Otherwise, connecting one Zoom server revokes the others."
	for _, code := range []string{"us.zoom/docs", "us.zoom/workspace", "us.zoom/team-chat", "us.zoom/whiteboard"} {
		server := mustCatalogServer(t, cat, code)
		require.NotNil(t, server.ConfigGuide, code)
		require.Equal(t, zoomAppHint, server.ConfigGuide.Note, code)
		require.Equal(t, []string{"Add TrustGate's OAuth callback URL, then enter the client ID."}, server.ConfigGuide.Steps, code)
	}
	revenue := mustCatalogServer(t, cat, "us.zoom/revenue-accelerator")
	require.Empty(t, revenue.ConfigGuide.Note)

	vanta := mustCatalogServer(t, cat, "com.vanta/mcp")
	require.Equal(t, []string{"mcp.vanta.com", "mcp.eu.vanta.com", "mcp.aus.vanta.com"},
		optionValues(variableByName(t, vanta, "host")))

	assembly := mustCatalogServer(t, cat, "com.assemblyai/docs")
	require.Equal(t, "https://mcp.assemblyai.com/docs", assembly.URL)
	require.Equal(t, authHintNone, assembly.AuthHint)

	halo := mustCatalogServer(t, cat, "com.haloitsm/mcp")
	require.Nil(t, halo.OAuth)
	require.Equal(t, authHintStatic, halo.AuthHint)
	require.Equal(t, "https://{instance}/api/mcp", halo.URL)
	require.Equal(t, "Bearer", halo.AuthHeaders[0].Scheme)
	require.Contains(t, halo.AuthHeaders[0].Description, "(we add 'Bearer')")
}

// Header placeholders name the secret the operator types. The gateway adds
// the scheme, so the description must not also start with that scheme.
func TestCuratedCatalog_HeaderPlaceholdersDoNotRepeatTheScheme(t *testing.T) {
	t.Parallel()
	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	for _, server := range cat.ListMCPServers() {
		for _, header := range server.AuthHeaders {
			scheme := strings.TrimSpace(header.Scheme)
			if scheme == "" || strings.EqualFold(scheme, "raw") {
				continue
			}
			desc := strings.TrimSpace(header.Description)
			require.Falsef(t, strings.HasPrefix(strings.ToLower(desc), strings.ToLower(scheme)+" "),
				"%s %s description %q starts with the scheme", server.Code, header.Name, desc)
			require.Falsef(t, strings.HasPrefix(strings.ToLower(desc), strings.ToLower(scheme)+"<"),
				"%s %s description %q starts with the scheme", server.Code, header.Name, desc)
		}
	}
}

func mustCatalogServer(t *testing.T, cat MCPServerCatalog, code string) domain.MCPServer {
	t.Helper()
	server, ok := cat.GetByCode(code)
	require.Truef(t, ok, "missing catalog entry %s", code)
	return server
}

func requireOAuth(t *testing.T, server domain.MCPServer, registration string, dcr bool, scopes []string) {
	t.Helper()
	require.NotNil(t, server.OAuth, server.Code)
	require.True(t, server.OAuth.Required, server.Code)
	require.Equal(t, registration, server.OAuth.Registration, server.Code)
	require.NotNil(t, server.OAuth.DCR, server.Code)
	require.Equal(t, dcr, *server.OAuth.DCR, server.Code)
	if scopes != nil {
		require.Equal(t, scopes, server.OAuth.Scopes, server.Code)
	}
}

func variableByName(t *testing.T, server domain.MCPServer, name string) domain.MCPURLVariable {
	t.Helper()
	for _, variable := range server.URLVariables {
		if variable.Name == name {
			return variable
		}
	}
	t.Fatalf("%s: missing url variable %q", server.Code, name)
	return domain.MCPURLVariable{}
}

func resolveCatalogURL(t *testing.T, server domain.MCPServer, values map[string]string) string {
	t.Helper()
	vars := make([]registrydomain.MCPURLVariable, 0, len(server.URLVariables))
	for _, variable := range server.URLVariables {
		vars = append(vars, asRegistryURLVariable(variable))
	}
	resolved, err := registrydomain.ResolveURL(server.URL, vars, values)
	require.NoError(t, err, server.Code)
	return resolved
}

func headerNames(server domain.MCPServer) []string {
	names := make([]string, 0, len(server.AuthHeaders))
	for _, header := range server.AuthHeaders {
		names = append(names, header.Name)
	}
	return names
}

func toolNames(server domain.MCPServer) []string {
	names := make([]string, 0, len(server.Tools))
	for _, tool := range server.Tools {
		names = append(names, tool.Name)
	}
	return names
}
