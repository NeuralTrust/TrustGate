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
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	// StoreToolNamePrefix namespaces the gateway-implemented Store meta-tools,
	// keeping them distinct from proxied upstream tools and from the connection
	// tools (trustgate_connect_*).
	StoreToolNamePrefix = "trustgate_store_"
	// StoreSearchToolName is the catalog-search meta-tool: it searches the whole
	// MCP catalog, not just what the caller has installed.
	StoreSearchToolName = StoreToolNamePrefix + "search"
	// StoreInstallToolName installs a catalog entry for the calling principal.
	StoreInstallToolName = StoreToolNamePrefix + "install"
	// StoreUninstallToolName removes a catalog entry the principal installed.
	StoreUninstallToolName = StoreToolNamePrefix + "uninstall"

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
	catalog    MCPServerCatalog
	installer  appstore.Installer
	registries appstore.RegistryLister
}

// NewStoreTool wires the catalog-search meta-tool (SEARCH only).
func NewStoreTool(catalog MCPServerCatalog) (StoreTool, error) {
	return NewStoreToolWithInstaller(catalog, nil, nil)
}

// NewStoreToolWithInstaller wires the Store meta-tools. When installer is nil
// only SEARCH is offered (e.g. a plane without the installation store); when
// registries is nil SEARCH does not tag results with their shelf state.
func NewStoreToolWithInstaller(
	catalog MCPServerCatalog,
	installer appstore.Installer,
	registries appstore.RegistryLister,
) (StoreTool, error) {
	if catalog == nil {
		return nil, ErrStoreToolUnavailable
	}
	return &storeTool{catalog: catalog, installer: installer, registries: registries}, nil
}

func (t *storeTool) Handles(name string) bool {
	return strings.HasPrefix(name, StoreToolNamePrefix)
}

func (t *storeTool) Definitions(_ context.Context, rc *appconsumer.RoutableConsumer) []Tool {
	if t == nil || t.catalog == nil || rc == nil {
		return nil
	}
	search, err := storeSearchDefinition()
	if err != nil {
		return nil
	}
	tools := []Tool{search}
	if t.installer != nil {
		if install, err := storeInstallDefinition(); err == nil {
			tools = append(tools, install)
		}
		if uninstall, err := storeUninstallDefinition(); err == nil {
			tools = append(tools, uninstall)
		}
	}
	return tools
}

func (t *storeTool) Call(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	if t == nil || t.catalog == nil || rc == nil || rc.Consumer == nil {
		return nil, ErrStoreToolUnavailable
	}
	switch name {
	case StoreSearchToolName:
		return t.search(ctx, rc, arguments)
	case StoreInstallToolName:
		return t.install(ctx, rc, arguments)
	case StoreUninstallToolName:
		return t.uninstall(ctx, rc, arguments)
	default:
		return nil, fmt.Errorf("%w: unknown tool %q", ErrStoreToolUnavailable, name)
	}
}

type storeCodeArgs struct {
	Code string `json:"code"`
}

func (t *storeTool) principalSubject(ctx context.Context) (string, error) {
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return "", ErrNoPrincipal
	}
	return principal.Subject, nil
}

func (t *storeTool) install(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	if t.installer == nil {
		return nil, fmt.Errorf("%w: install is not available here", ErrStoreToolUnavailable)
	}
	var args storeCodeArgs
	if err := json.Unmarshal(arguments, &args); err != nil || strings.TrimSpace(args.Code) == "" {
		return nil, fmt.Errorf("%w: install requires a catalog code", ErrStoreToolUnavailable)
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return nil, ErrNoPrincipal
	}
	res, err := t.installer.Install(ctx, appstore.InstallRequest{
		GatewayID:    rc.Consumer.GatewayID,
		PrincipalSub: principal.Subject,
		Code:         args.Code,
		InstalledBy:  principal.Subject,
		Groups:       principalGroups(principal),
	})
	if err != nil {
		return nil, err
	}
	text := installMessage(res)
	return marshalToolResult(text, map[string]any{
		"code":              res.Code,
		"name":              res.Name,
		"status":            string(res.Status),
		"pending":           res.Pending,
		"requires_auth":     res.RequiresAuth,
		"already_installed": res.AlreadyInstalled,
	})
}

func (t *storeTool) uninstall(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	if t.installer == nil {
		return nil, fmt.Errorf("%w: uninstall is not available here", ErrStoreToolUnavailable)
	}
	var args storeCodeArgs
	if err := json.Unmarshal(arguments, &args); err != nil || strings.TrimSpace(args.Code) == "" {
		return nil, fmt.Errorf("%w: uninstall requires a catalog code", ErrStoreToolUnavailable)
	}
	sub, err := t.principalSubject(ctx)
	if err != nil {
		return nil, err
	}
	if err := t.installer.Uninstall(ctx, rc.Consumer.GatewayID, sub, args.Code); err != nil {
		return nil, err
	}
	return marshalToolResult(
		fmt.Sprintf("Uninstalled %s.", strings.TrimSpace(args.Code)),
		map[string]any{"code": strings.TrimSpace(args.Code), "uninstalled": true},
	)
}

func principalGroups(principal *identity.Principal) []string {
	if principal == nil {
		return nil
	}
	switch v := principal.Claims[identity.ClaimGroups].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func installMessage(res *appstore.InstallResult) string {
	if res.AlreadyInstalled {
		return fmt.Sprintf("%s was already installed.", res.Name)
	}
	if res.Pending {
		return fmt.Sprintf("%s has been requested and is awaiting approval; you'll get its tools once an admin approves it.", res.Name)
	}
	text := fmt.Sprintf("Installed %s.", res.Name)
	if res.RequiresAuth {
		text += " It needs your account connected before its tools can be used."
	}
	return text
}

func marshalToolResult(text string, structured map[string]any) (json.RawMessage, error) {
	raw, err := json.Marshal(map[string]any{
		"content":           []map[string]string{{"type": "text", "text": text}},
		"structuredContent": structured,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: encode result: %w", ErrStoreToolUnavailable, err)
	}
	return raw, nil
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
	// StoreState is how the caller can obtain this server: "available" (installs
	// immediately), "approval" (install needs approval), or "request" (not on the
	// admin's shelf yet — installing files a request).
	StoreState string `json:"store_state"`
}

const (
	storeStateAvailable = "available"
	storeStateApproval  = "approval"
	storeStateRequest   = "request"
)

type shelfEntry struct {
	available        bool
	requiresApproval bool
}

func (t *storeTool) search(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	arguments json.RawMessage,
) (json.RawMessage, error) {
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

	shelf := t.shelfIndex(ctx, rc)
	curated := t.storeMode(ctx) == gatewaydomain.StoreModeCurated

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
		state := shelfState(shelf, entry.Code)
		// In curated mode only shelf (available) servers are browsable.
		if curated && state == storeStateRequest {
			continue
		}
		total++
		if len(matched) < limit {
			matched = append(matched, toSearchResult(entry, state))
		}
	}

	structured := map[string]any{
		"results":   matched,
		"total":     total,
		"returned":  len(matched),
		"truncated": total > len(matched),
		"mode":      t.storeMode(ctx),
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

// shelfIndex maps catalog codes the admin has put on this gateway's shelf to
// their Store governance. Empty when registries are not wired (data plane).
func (t *storeTool) shelfIndex(ctx context.Context, rc *appconsumer.RoutableConsumer) map[string]shelfEntry {
	if t.registries == nil || rc == nil || rc.Consumer == nil {
		return nil
	}
	items, _, err := t.registries.List(ctx, registrydomain.ListFilter{
		GatewayID: rc.Consumer.GatewayID,
		Page:      1,
		Size:      storeShelfPageSize,
	})
	if err != nil {
		return nil
	}
	shelf := make(map[string]shelfEntry, len(items))
	for _, reg := range items {
		if reg == nil || reg.MCPTarget == nil || reg.MCPTarget.Code == "" {
			continue
		}
		shelf[reg.MCPTarget.Code] = shelfEntry{
			available:        reg.MCPTarget.StoreAvailable(),
			requiresApproval: reg.MCPTarget.StoreRequiresApproval(),
		}
	}
	return shelf
}

func (t *storeTool) storeMode(ctx context.Context) string {
	if gw, ok := appgateway.FromContext(ctx); ok {
		return gw.StoreMode()
	}
	return gatewaydomain.StoreModeOpen
}

const storeShelfPageSize = 500

func shelfState(shelf map[string]shelfEntry, code string) string {
	entry, ok := shelf[code]
	if !ok || !entry.available {
		return storeStateRequest
	}
	if entry.requiresApproval {
		return storeStateApproval
	}
	return storeStateAvailable
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

func toSearchResult(entry catalogdomain.MCPServer, state string) storeSearchResult {
	return storeSearchResult{
		Code:         entry.Code,
		Name:         entry.DisplayName,
		Vendor:       entry.Vendor,
		Category:     entry.Category,
		Description:  entry.Description,
		ToolCount:    len(entry.Tools),
		RequiresAuth: entry.RequiresAuth,
		StoreState:   state,
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

func storeInstallDefinition() (Tool, error) {
	return codeArgTool(
		StoreInstallToolName,
		"Install an MCP server",
		"Install a catalog MCP server for the current user so its tools appear on this Store. Takes the catalog `code` returned by "+StoreSearchToolName+". Governed by the user's role; a server that needs the user's own account will ask them to connect it before its tools work.",
		false,
	)
}

func storeUninstallDefinition() (Tool, error) {
	return codeArgTool(
		StoreUninstallToolName,
		"Uninstall an MCP server",
		"Remove a catalog MCP server the current user installed, taking its tools off this Store. Takes the catalog `code`.",
		true,
	)
}

func codeArgTool(name, title, description string, idempotent bool) (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":        name,
		"title":       title,
		"description": description,
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"code": map[string]any{
					"type":        "string",
					"description": "Catalog code of the MCP server.",
				},
			},
			"required":             []string{"code"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    false,
			"destructiveHint": idempotent,
			"idempotentHint":  idempotent,
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
