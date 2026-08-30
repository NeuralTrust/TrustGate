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

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

const (
	// StoreToolNamePrefix namespaces the gateway-implemented Store meta-tools,
	// keeping them distinct from proxied upstream tools and from the connection
	// tools (trustgate_connect_*).
	StoreToolNamePrefix = "trustgate_store_"
	// StoreSearchToolName is the catalog-search meta-tool: it searches the whole
	// MCP catalog, not just what the caller has installed.
	StoreSearchToolName = StoreToolNamePrefix + "search"

	defaultStoreSearchLimit = 20
	maxStoreSearchLimit     = 50
)

// ErrStoreToolUnavailable is returned when the Store meta-tools cannot serve a
// request (unconfigured catalog, or an unknown meta-tool name).
var ErrStoreToolUnavailable = errors.New("mcp: store tool unavailable")

// MCPServerCatalog is the read side of the curated MCP-server catalog the Store
// searches over. It is a narrow local view of the catalog service.
type MCPServerCatalog interface {
	ListMCPServers() []catalogdomain.MCPServer
}

// StoreTool implements the MCP Store's gateway-side meta-tools (SEARCH today;
// INSTALL and friends later). It mirrors ConnectionTool but its Call takes
// arguments, since a search carries a query.
type StoreTool interface {
	Definitions(ctx context.Context, rc *appconsumer.RoutableConsumer) []Tool
	Handles(name string) bool
	Call(ctx context.Context, rc *appconsumer.RoutableConsumer, name string, arguments json.RawMessage) (json.RawMessage, error)
}

type storeTool struct {
	catalog MCPServerCatalog
}

// NewStoreTool wires the Store meta-tools over the catalog service.
func NewStoreTool(catalog MCPServerCatalog) (StoreTool, error) {
	if catalog == nil {
		return nil, ErrStoreToolUnavailable
	}
	return &storeTool{catalog: catalog}, nil
}

func (t *storeTool) Handles(name string) bool {
	return strings.HasPrefix(name, StoreToolNamePrefix)
}

func (t *storeTool) Definitions(_ context.Context, rc *appconsumer.RoutableConsumer) []Tool {
	if t == nil || t.catalog == nil || rc == nil {
		return nil
	}
	def, err := storeSearchDefinition()
	if err != nil {
		return nil
	}
	return []Tool{def}
}

func (t *storeTool) Call(
	_ context.Context,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	if t == nil || t.catalog == nil || rc == nil {
		return nil, ErrStoreToolUnavailable
	}
	switch name {
	case StoreSearchToolName:
		return t.search(arguments)
	default:
		return nil, fmt.Errorf("%w: unknown tool %q", ErrStoreToolUnavailable, name)
	}
}

type storeSearchArgs struct {
	Query    string `json:"query"`
	Category string `json:"category"`
	Limit    int    `json:"limit"`
}

type storeSearchResult struct {
	Code         string `json:"code"`
	Name         string `json:"name"`
	Vendor       string `json:"vendor,omitempty"`
	Category     string `json:"category,omitempty"`
	Description  string `json:"description,omitempty"`
	ToolCount    int    `json:"tool_count"`
	RequiresAuth bool   `json:"requires_auth"`
}

func (t *storeTool) search(arguments json.RawMessage) (json.RawMessage, error) {
	var args storeSearchArgs
	if len(arguments) > 0 {
		// Be lenient: a malformed argument object browses the catalog rather than
		// failing the call — search is read-only and self-correcting.
		_ = json.Unmarshal(arguments, &args)
	}
	limit := args.Limit
	if limit <= 0 {
		limit = defaultStoreSearchLimit
	}
	if limit > maxStoreSearchLimit {
		limit = maxStoreSearchLimit
	}
	query := strings.ToLower(strings.TrimSpace(args.Query))
	category := strings.ToLower(strings.TrimSpace(args.Category))

	// The catalog is served in relevance order; a query narrows it, an empty
	// query browses the top of the whole catalog.
	all := t.catalog.ListMCPServers()
	matched := make([]storeSearchResult, 0, limit)
	total := 0
	for i := range all {
		entry := all[i]
		if category != "" && strings.ToLower(strings.TrimSpace(entry.Category)) != category {
			continue
		}
		if !matchesQuery(entry, query) {
			continue
		}
		total++
		if len(matched) < limit {
			matched = append(matched, toSearchResult(entry))
		}
	}

	structured := map[string]any{
		"results":   matched,
		"total":     total,
		"returned":  len(matched),
		"truncated": total > len(matched),
	}
	result := map[string]any{
		"content": []map[string]string{{
			"type": "text",
			"text": searchSummary(query, category, total, len(matched)),
		}},
		"structuredContent": structured,
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("%w: encode result: %w", ErrStoreToolUnavailable, err)
	}
	return raw, nil
}

func matchesQuery(entry catalogdomain.MCPServer, query string) bool {
	if query == "" {
		return true
	}
	for _, field := range []string{
		entry.Code, entry.DisplayName, entry.Vendor, entry.Category, entry.Description,
	} {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

func toSearchResult(entry catalogdomain.MCPServer) storeSearchResult {
	return storeSearchResult{
		Code:         entry.Code,
		Name:         entry.DisplayName,
		Vendor:       entry.Vendor,
		Category:     entry.Category,
		Description:  entry.Description,
		ToolCount:    len(entry.Tools),
		RequiresAuth: entry.RequiresAuth,
	}
}

func searchSummary(query, category string, total, returned int) string {
	var b strings.Builder
	if returned == 0 {
		b.WriteString("No MCP servers in the catalog match")
	} else if returned < total {
		fmt.Fprintf(&b, "Showing %d of %d matching MCP servers", returned, total)
	} else {
		fmt.Fprintf(&b, "Found %d matching MCP server(s)", total)
	}
	if query != "" {
		fmt.Fprintf(&b, " for %q", query)
	}
	if category != "" {
		fmt.Fprintf(&b, " in category %q", category)
	}
	b.WriteString(".")
	return b.String()
}

func storeSearchDefinition() (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":        StoreSearchToolName,
		"title":       "Search the MCP catalog",
		"description": "Search the whole NeuralTrust MCP catalog for servers to install (not just the ones already installed). Call this when the user wants to find, browse or discover an MCP integration by name, vendor, category or capability. Returns catalog entries with their code, which INSTALL takes.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "Free-text search over name, vendor, category and description. Empty browses the top of the catalog.",
				},
				"category": map[string]any{
					"type":        "string",
					"description": "Optional exact category filter.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": "Maximum results to return (default 20, max 50).",
					"minimum":     1,
					"maximum":     maxStoreSearchLimit,
				},
			},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    true,
			"destructiveHint": false,
			"idempotentHint":  true,
			"openWorldHint":   false,
		},
	})
	if err != nil {
		return Tool{}, err
	}
	var def Tool
	if err := json.Unmarshal(raw, &def); err != nil {
		return Tool{}, err
	}
	return def, nil
}
