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
