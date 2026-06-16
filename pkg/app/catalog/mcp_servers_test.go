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

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/catalog"
	"github.com/stretchr/testify/require"
)

func TestNewMCPServerCatalog_LoadsCuratedList(t *testing.T) {
	t.Parallel()

	cat, err := NewMCPServerCatalog()
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

	cat, err := NewMCPServerCatalog()
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
