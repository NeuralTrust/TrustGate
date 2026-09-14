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

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/stretchr/testify/require"
)

func TestCatalogCapabilities_PrefersSeed(t *testing.T) {
	t.Parallel()

	got := catalogCapabilities(
		[]string{"Read published docs", "Search the knowledge base"},
		[]domain.MCPTool{{Name: "search_pages"}},
	)
	require.Equal(t, []string{
		"Read published docs",
		"Search the knowledge base",
		"Search and read content",
	}, got)
}

func TestCatalogCapabilities_DerivesFromTools(t *testing.T) {
	t.Parallel()

	got := catalogCapabilities(nil, []domain.MCPTool{
		{Name: "ping"},
		{Name: "search_pages", Description: "Search workspace and connected sources."},
		{Name: "create_page"},
	})
	require.Equal(t, []string{
		"Search workspace and connected sources",
		"Create page",
		"Search and read content",
	}, got)
}

func TestParseCuratedMCPServers_ExposesCapabilities(t *testing.T) {
	t.Parallel()

	data := []byte(`{"servers":[{
		"name":"com.acme/mcp",
		"vendor":"Acme",
		"transport":"streamable-http",
		"server_url":"https://a.example.com/mcp",
		"self_service":false,
		"multi_instance":false,
		"tools":[{"name":"search_pages"}]
	}]}`)

	servers, err := parseCuratedMCPServers(data)
	require.NoError(t, err)
	require.Len(t, servers, 1)
	require.Equal(t, []string{
		"Search pages",
		"Search and read content",
		"Create and update records",
	}, servers[0].Capabilities)
}
