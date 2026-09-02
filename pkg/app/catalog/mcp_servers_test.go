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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/stretchr/testify/require"
)

func TestNewMCPServerCatalog_LoadsCuratedList(t *testing.T) {
	t.Parallel()

	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	servers := cat.ListMCPServers()
	require.NotEmpty(t, servers)

	codes := make(map[string]struct{}, len(servers))
	for _, s := range servers {
		require.NotEmpty(t, s.Code, "code must be set")
		require.NotEmpty(t, s.URL, "url must be set for %q", s.Code)
		require.NotEmpty(t, s.Transport, "transport must be set for %q", s.Code)
		require.Equal(t, curatedSource, s.Source)
		require.Contains(t, []string{authHintNone, authHintStatic, authHintOAuth}, s.AuthHint,
			"unexpected auth hint %q for %q", s.AuthHint, s.Code)

		_, dup := codes[s.Code]
		require.Falsef(t, dup, "duplicate code %q", s.Code)
		codes[s.Code] = struct{}{}
	}
}

func TestListMCPServers_SortedByRelevanceDesc(t *testing.T) {
	t.Parallel()

	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)
	servers := cat.ListMCPServers()
	require.NotEmpty(t, servers)

	// Relevance must be non-increasing across the list.
	for i := 1; i < len(servers); i++ {
		require.GreaterOrEqualf(t, servers[i-1].Relevance, servers[i].Relevance,
			"relevance not sorted desc at %d (%q=%d before %q=%d)",
			i, servers[i-1].Code, servers[i-1].Relevance, servers[i].Code, servers[i].Relevance)
	}

	// The first entry must be a ranked (relevant) server, not an unranked one.
	require.Greater(t, servers[0].Relevance, 0, "top entry should be a ranked server")
}

func TestParseCuratedMCPServers_RejectsDuplicateCode(t *testing.T) {
	t.Parallel()

	data := []byte(`{"servers":[
		{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp"},
		{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://b.example.com/mcp"}
	]}`)

	_, err := parseCuratedMCPServers(data)
	require.ErrorContains(t, err, "duplicate server code")
	require.ErrorContains(t, err, "com.acme/mcp")
}

func TestParseCuratedMCPServers_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	data := []byte(`{"servers":[
		{"name":"","transport":"streamable-http","server_url":"https://a.example.com/mcp"}
	]}`)

	_, err := parseCuratedMCPServers(data)
	require.ErrorContains(t, err, "empty name")
}

func TestParseCuratedMCPServers_AcceptsUniqueCodes(t *testing.T) {
	t.Parallel()

	data := []byte(`{"servers":[
		{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp"},
		{"name":"com.beta/mcp","transport":"streamable-http","server_url":"https://b.example.com/mcp"}
	]}`)

	servers, err := parseCuratedMCPServers(data)
	require.NoError(t, err)
	require.Len(t, servers, 2)
}

func TestParseCuratedMCPServers_OmitsHidden(t *testing.T) {
	t.Parallel()

	data := []byte(`{"servers":[
		{"name":"com.acme/mcp","transport":"streamable-http","server_url":"https://a.example.com/mcp"},
		{"name":"com.hidden/mcp","transport":"streamable-http","server_url":"https://h.example.com/mcp","hidden":true,"hidden_reason":"broken"},
		{"name":"com.beta/mcp","transport":"streamable-http","server_url":"https://b.example.com/mcp","hidden":false}
	]}`)

	servers, err := parseCuratedMCPServers(data)
	require.NoError(t, err)
	require.Len(t, servers, 2)
	codes := []string{servers[0].Code, servers[1].Code}
	require.Contains(t, codes, "com.acme/mcp")
	require.Contains(t, codes, "com.beta/mcp")
	require.NotContains(t, codes, "com.hidden/mcp")
}

func TestAuthHint_Classification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   rawServer
		want string
	}{
		{
			name: "oauth required",
			in:   rawServer{RequiresAuth: true, OAuth: &domain.MCPOAuth{Required: true}},
			want: authHintOAuth,
		},
		{
			name: "auth headers => static",
			in: rawServer{
				RequiresAuth: true,
				AuthHeaders:  []domain.MCPAuthHeader{{Name: "Authorization", Required: true, Secret: true}},
			},
			want: authHintStatic,
		},
		{
			name: "requires auth without headers/oauth => static",
			in:   rawServer{RequiresAuth: true},
			want: authHintStatic,
		},
		{
			name: "public => none",
			in:   rawServer{RequiresAuth: false},
			want: authHintNone,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, authHint(tc.in))
		})
	}
}

func TestRequiresConfig_Classification(t *testing.T) {
	t.Parallel()

	boolPtr := func(b bool) *bool { return &b }

	tests := []struct {
		name string
		in   rawServer
		want bool
	}{
		{
			name: "public, no url vars => connect by default",
			in:   rawServer{RequiresAuth: false},
			want: false,
		},
		{
			name: "oauth auto, no url vars => connect by default",
			in:   rawServer{OAuth: &domain.MCPOAuth{Required: true, Registration: "auto", DCR: boolPtr(true)}},
			want: false,
		},
		{
			name: "oauth manual => needs config",
			in:   rawServer{OAuth: &domain.MCPOAuth{Required: true, Registration: "manual", DCR: boolPtr(false)}},
			want: true,
		},
		{
			name: "oauth unknown registration (tenant) => needs config",
			in:   rawServer{OAuth: &domain.MCPOAuth{Required: true}},
			want: true,
		},
		{
			name: "static secret => needs config",
			in: rawServer{
				RequiresAuth: true,
				AuthHeaders:  []domain.MCPAuthHeader{{Name: "Authorization", Required: true, Secret: true}},
			},
			want: true,
		},
		{
			name: "oauth client_credentials => needs config",
			in: rawServer{OAuth: &domain.MCPOAuth{
				Required:  true,
				GrantType: "client_credentials",
				TokenURL:  "https://idp.example/token",
			}},
			want: true,
		},
		{
			name: "oauth auto but required url var (tenant host) => needs config",
			in: rawServer{
				OAuth:        &domain.MCPOAuth{Required: true, Registration: "auto", DCR: boolPtr(true)},
				URLVariables: []domain.MCPURLVariable{{Name: "domain", Required: true}},
			},
			want: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, requiresConfig(tc.in))
		})
	}
}

func TestNewMCPServerCatalog_IncludesSectigoN8nHalo(t *testing.T) {
	t.Parallel()
	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	sectigo, ok := cat.GetByCode("com.sectigo/mcp")
	require.True(t, ok)
	require.Equal(t, "https://mcp.{instance}.sectigo.com/mcp", sectigo.URL)
	require.Equal(t, authHintOAuth, sectigo.AuthHint)
	require.True(t, sectigo.RequiresConfig)
	require.NotNil(t, sectigo.OAuth)
	require.Equal(t, "client_credentials", sectigo.OAuth.GrantType)
	require.Contains(t, sectigo.OAuth.TokenURL, "auth.sso.sectigo.com")

	n8n, ok := cat.GetByCode("io.n8n/mcp")
	require.True(t, ok)
	require.Equal(t, "https://{domain}/mcp-server/http", n8n.URL)
	require.Equal(t, authHintOAuth, n8n.AuthHint)
	require.True(t, n8n.RequiresConfig)
	require.Equal(t, "auto", n8n.OAuth.Registration)

	halo, ok := cat.GetByCode("com.haloitsm/mcp")
	require.True(t, ok)
	require.Equal(t, "https://{instance}/api/mcp", halo.URL)
	require.Equal(t, authHintStatic, halo.AuthHint)
	require.True(t, halo.RequiresConfig)
	require.NotEmpty(t, halo.AuthHeaders)
}

func TestNewMCPServerCatalog_IncludesAWSManagedServer(t *testing.T) {
	t.Parallel()

	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	server, ok := cat.GetByCode("com.amazon.aws/mcp")
	require.True(t, ok)
	require.Equal(t, "https://aws-mcp.{region}.api.aws/mcp", server.URL)
	require.Equal(t, "AWS", server.Vendor)
	require.Equal(t, authHintOAuth, server.AuthHint)
	require.True(t, server.RequiresConfig)
	require.Len(t, server.URLVariables, 1)
	require.Equal(t, "region", server.URLVariables[0].Name)
	require.True(t, server.URLVariables[0].Required)
	require.NotNil(t, server.OAuth)
	require.Equal(t, "auto", server.OAuth.Registration)
	require.NotNil(t, server.OAuth.DCR)
	require.True(t, *server.OAuth.DCR)
	require.NotNil(t, server.OAuth.PKCE)
	require.True(t, *server.OAuth.PKCE)
	// AWS publishes region-specific OAuth endpoints through protected-resource
	// metadata, so the seed leaves them out and lets discovery resolve them
	// against the region the operator picked.
	require.Empty(t, server.OAuth.AuthorizeURL)
	require.Empty(t, server.OAuth.TokenURL)
	require.Empty(t, server.OAuth.Resource)
}

// A templated oauth.resource never reaches substitution: the registry
// canonicalizer copies it verbatim and the provider client sends it as the
// RFC 8707 resource indicator, so the authorization server would receive a
// literal "{placeholder}" and reject the grant. Entries that need a
// per-instance audience set resource_metadata instead, which resolves to the
// registry's own URL after URL variables are applied.
func TestCuratedCatalog_HasNoTemplatedOAuthResource(t *testing.T) {
	t.Parallel()

	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	for _, server := range cat.ListMCPServers() {
		if server.OAuth == nil {
			continue
		}
		require.NotContains(t, server.OAuth.Resource, "{",
			"catalog entry %q declares a templated oauth.resource", server.Code)
	}
}

func TestNewMCPServerCatalog_IncludesJotformStoryblokAndHolded(t *testing.T) {
	t.Parallel()

	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)

	tests := []struct {
		code           string
		url            string
		authorizeURL   string
		tokenURL       string
		resource       string
		registration   string
		dcr            bool
		requiresConfig bool
		scopes         []string
		tools          []string
		assertTools    bool
	}{
		{
			code:           "com.jotform/mcp",
			url:            "https://mcp.jotform.com",
			authorizeURL:   "https://oauth2.jotform.com/authorize",
			tokenURL:       "https://oauth2.jotform.com/token",
			resource:       "https://mcp.jotform.com/mcp",
			registration:   "manual",
			dcr:            false,
			requiresConfig: true,
			scopes:         []string{"full"},
			tools:          []string{"form_list", "create_form", "edit_form", "create_submission", "get_submissions"},
			assertTools:    true,
		},
		{
			code:         "com.storyblok/mcp",
			url:          "https://mcp.storyblok.com/mcp",
			authorizeURL: "https://mcp.storyblok.com/oauth/authorize",
			tokenURL:     "https://mcp.storyblok.com/oauth/token",
			resource:     "https://mcp.storyblok.com/mcp",
			registration: "auto",
			dcr:          true,
			tools:        []string{"search", "describe", "execute_readonly", "execute_mutating", "execute_destructive", "upload_asset", "upload_asset_finish"},
			assertTools:  true,
		},
		{
			code:         "com.holded/mcp",
			url:          "https://mcp.holded.com/mcp",
			authorizeURL: "https://app.holded.com/api/v2/mcp/oauth/authorize",
			tokenURL:     "https://app.holded.com/api/v2/mcp/oauth/token",
			resource:     "https://mcp.holded.com/mcp",
			registration: "auto",
			dcr:          true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()

			server, ok := cat.GetByCode(tc.code)
			require.True(t, ok)
			require.Equal(t, tc.url, server.URL)
			require.Equal(t, authHintOAuth, server.AuthHint)
			require.Equal(t, tc.requiresConfig, server.RequiresConfig)
			require.NotNil(t, server.OAuth)
			require.Equal(t, tc.registration, server.OAuth.Registration)
			require.NotNil(t, server.OAuth.DCR)
			require.Equal(t, tc.dcr, *server.OAuth.DCR)
			require.NotNil(t, server.OAuth.PKCE)
			require.True(t, *server.OAuth.PKCE)
			require.Equal(t, tc.authorizeURL, server.OAuth.AuthorizeURL)
			require.Equal(t, tc.tokenURL, server.OAuth.TokenURL)
			require.Equal(t, tc.resource, server.OAuth.Resource)
			require.Equal(t, tc.scopes, server.OAuth.Scopes)

			toolNames := make([]string, 0, len(server.Tools))
			for _, tool := range server.Tools {
				toolNames = append(toolNames, tool.Name)
			}
			if tc.assertTools {
				require.Equal(t, tc.tools, toolNames)
			}
		})
	}
}

func TestNewMCPServerCatalog_GoogleWorkspacePlatformClient(t *testing.T) {
	t.Parallel()

	without, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)
	gmail, ok := without.GetByCode("com.google.workspace/gmail")
	require.True(t, ok)
	require.True(t, gmail.RequiresConfig)
	require.False(t, gmail.PlatformClient)
	calendar, ok := without.GetByCode("com.google.workspace/calendar")
	require.True(t, ok)
	require.True(t, calendar.RequiresConfig)
	require.False(t, calendar.PlatformClient)
	drive, ok := without.GetByCode("com.google.workspace/drive")
	require.True(t, ok)
	require.True(t, drive.RequiresConfig)
	require.False(t, drive.PlatformClient)
	require.Equal(t, "https://drivemcp.googleapis.com/mcp/v1", drive.URL)

	with, err := NewMCPServerCatalog(mcpoauth.NewGoogleWorkspace("nt-client", "nt-secret"))
	require.NoError(t, err)
	gmail, ok = with.GetByCode("com.google.workspace/gmail")
	require.True(t, ok)
	require.False(t, gmail.RequiresConfig)
	require.True(t, gmail.PlatformClient)
	calendar, ok = with.GetByCode("com.google.workspace/calendar")
	require.True(t, ok)
	require.False(t, calendar.RequiresConfig)
	require.True(t, calendar.PlatformClient)
	drive, ok = with.GetByCode("com.google.workspace/drive")
	require.True(t, ok)
	require.False(t, drive.RequiresConfig)
	require.True(t, drive.PlatformClient)

	linear, ok := with.GetByCode("app.linear/mcp")
	require.True(t, ok)
	require.False(t, linear.PlatformClient)
	id, secret, ok := with.SharedOAuthCredentials("com.google.workspace/gmail")
	require.True(t, ok)
	require.Equal(t, "nt-client", id)
	require.Equal(t, "nt-secret", secret)
	_, _, ok = with.SharedOAuthCredentials("app.linear/mcp")
	require.False(t, ok)
}

func TestNewMCPServerCatalog_GmailIncludesModifyScope(t *testing.T) {
	t.Parallel()

	cat, err := NewMCPServerCatalog(nil)
	require.NoError(t, err)
	gmail, ok := cat.GetByCode("com.google.workspace/gmail")
	require.True(t, ok)
	require.NotNil(t, gmail.OAuth)
	require.Contains(t, gmail.OAuth.Scopes, "https://www.googleapis.com/auth/gmail.readonly")
	require.Contains(t, gmail.OAuth.Scopes, "https://www.googleapis.com/auth/gmail.compose")
	require.Contains(t, gmail.OAuth.Scopes, "https://www.googleapis.com/auth/gmail.modify")

	tools := make([]string, 0, len(gmail.Tools))
	for _, tool := range gmail.Tools {
		tools = append(tools, tool.Name)
	}
	require.Contains(t, tools, "label_thread")
	require.Contains(t, tools, "create_label")
}
