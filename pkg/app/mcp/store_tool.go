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
	"net/url"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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

// ConfigureGateway mints a ticket for the hosted "configure" form where a user
// enters a server's per-user URL variables (e.g. a Snowflake account URL, a
// secret token). appoauth.ConfigureService satisfies it. Optional: without it the
// install tool still works but returns no configure link.
type ConfigureGateway interface {
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath, code string) (string, error)
}

// ServerConnectGateway mints a connect ticket scoped to one catalog server, so
// the install's OAuth connect link opens the focused single-server connect page.
// appoauth.ConnectService satisfies it.
type ServerConnectGateway interface {
	CreateServerTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath, code string) (string, error)
}

// StoreTool implements the MCP Store's gateway-side meta-tools (SEARCH today;
// INSTALL and friends later). It mirrors ConnectionTool but its Call takes
// arguments, since a search carries a query.
type StoreTool interface {
	Definitions(ctx context.Context, rc *appconsumer.RoutableConsumer) []Tool
	Handles(name string) bool
	Call(ctx context.Context, rc *appconsumer.RoutableConsumer, baseURL, name string, arguments json.RawMessage) (json.RawMessage, error)
}

type storeTool struct {
	catalog    MCPServerCatalog
	installer  appstore.Installer
	registries appstore.RegistryLister
	configure  ConfigureGateway
	connect    ServerConnectGateway
}

// NewStoreTool wires the catalog-search meta-tool (SEARCH only).
func NewStoreTool(catalog MCPServerCatalog) (StoreTool, error) {
	return NewStoreToolWithInstaller(catalog, nil, nil, nil, nil)
}

// NewStoreToolWithInstaller wires the Store meta-tools. When installer is nil
// only SEARCH is offered (e.g. a plane without the installation store); when
// registries is nil SEARCH does not tag results with their shelf state; when
// configure is nil an install that needs per-user setup returns the variable list
// but no hosted-form link; when connect is nil an install that needs the user's
// account returns requires_auth but no OAuth connect link.
func NewStoreToolWithInstaller(
	catalog MCPServerCatalog,
	installer appstore.Installer,
	registries appstore.RegistryLister,
	configure ConfigureGateway,
	connect ServerConnectGateway,
) (StoreTool, error) {
	if catalog == nil {
		return nil, ErrStoreToolUnavailable
	}
	return &storeTool{
		catalog:    catalog,
		installer:  installer,
		registries: registries,
		configure:  configure,
		connect:    connect,
	}, nil
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
	baseURL,
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
		return t.install(ctx, rc, baseURL, arguments)
	case StoreUninstallToolName:
		return t.uninstall(ctx, rc, arguments)
	default:
		return nil, fmt.Errorf("%w: unknown tool %q", ErrStoreToolUnavailable, name)
	}
}

type storeCodeArgs struct {
	Code string `json:"code"`
}

// storeInstallArgs is the install meta-tool's input: the catalog code plus the
// per-user URL-variable values (config), collected from the user for servers that
// declare them (e.g. Snowflake's account_url/database).
type storeInstallArgs struct {
	Code   string            `json:"code"`
	Config map[string]string `json:"config,omitempty"`
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
	baseURL string,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	if t.installer == nil {
		return nil, fmt.Errorf("%w: install is not available here", ErrStoreToolUnavailable)
	}
	var args storeInstallArgs
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
		OpenMode:     t.storeMode(ctx) == gatewaydomain.StoreModeOpen,
		Config:       args.Config,
	})
	if err != nil {
		return nil, err
	}
	// A server that needs per-user setup gets a hosted-form link the user opens to
	// enter their values (the only path for secrets, and a nicer one for the rest).
	configureURL := ""
	if res.RequiresConfig {
		configureURL = t.configureLink(ctx, rc, baseURL, res.Code)
	}
	// A server that needs the user's own account gets the OAuth connect link right
	// in the install result — the second step of the install, so the user does not
	// have to hunt for it in their client.
	connectURL := ""
	if res.RequiresAuth && !res.AlreadyInstalled {
		connectURL = t.connectLink(ctx, rc, baseURL, res.Code)
	}
	structured := map[string]any{
		"code":              res.Code,
		"name":              res.Name,
		"status":            string(res.Status),
		"pending":           res.Pending,
		"requires_auth":     res.RequiresAuth,
		"already_installed": res.AlreadyInstalled,
		"requires_config":   res.RequiresConfig,
		"config_variables":  configVariablesJSON(res.ConfigVariables),
	}
	if configureURL != "" {
		structured["configure_url"] = configureURL
	}
	if connectURL != "" {
		structured["connect_url"] = connectURL
	}
	return marshalToolResult(installMessage(res, configureURL, connectURL), structured)
}

// connectLink mints an OAuth connect ticket and builds the hosted connect-page
// URL, or "" when no connect gateway is wired. Non-fatal on failure: the install
// still stands and the user can connect later.
func (t *storeTool) connectLink(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	baseURL, code string,
) string {
	if t.connect == nil || strings.TrimSpace(baseURL) == "" {
		return ""
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return ""
	}
	consumerPath := appconsumer.MCPPath(rc.Consumer.Slug)
	ticket, err := t.connect.CreateServerTicket(ctx, rc.Consumer.GatewayID, principal.Subject, consumerPath, code)
	if err != nil {
		return ""
	}
	url, err := buildConnectionURL(baseURL, consumerPath, ticket)
	if err != nil {
		return ""
	}
	return url
}

// configureLink mints a configure ticket and builds the hosted-form URL, or
// returns "" when no configure gateway is wired (the caller then falls back to
// inline config only). A failure to mint is non-fatal: the install still stands.
func (t *storeTool) configureLink(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	baseURL, code string,
) string {
	if t.configure == nil || strings.TrimSpace(baseURL) == "" {
		return ""
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return ""
	}
	consumerPath := appconsumer.MCPPath(rc.Consumer.Slug)
	ticket, err := t.configure.CreateTicket(ctx, rc.Consumer.GatewayID, principal.Subject, consumerPath, code)
	if err != nil {
		return ""
	}
	url, err := buildConfigureURL(baseURL, consumerPath, ticket)
	if err != nil {
		return ""
	}
	return url
}

// configVariablesJSON renders the required-config variables for the tool result
// so the caller (the model) knows exactly what to collect and re-submit.
func configVariablesJSON(vars []registrydomain.MCPURLVariable) []map[string]any {
	if len(vars) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(vars))
	for _, v := range vars {
		out = append(out, map[string]any{
			"name":        v.Name,
			"description": v.Description,
			"required":    v.Required,
			"secret":      v.Secret,
		})
	}
	return out
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

func installMessage(res *appstore.InstallResult, configureURL, connectURL string) string {
	if res.AlreadyInstalled {
		return fmt.Sprintf("%s was already installed.", res.Name)
	}
	if res.RequiresConfig {
		return requiresConfigMessage(res, configureURL)
	}
	if res.Pending {
		return fmt.Sprintf("%s has been requested and is awaiting approval; you'll get its tools once an admin approves it.", res.Name)
	}
	text := fmt.Sprintf("Installed %s.", res.Name)
	if res.RequiresAuth {
		if connectURL != "" {
			// The connect link is the second install step; the tools appear once the
			// user authorizes their account.
			text += fmt.Sprintf(" Connect your account to finish: %s — present this link to the user and let them open it. Once they authorize, its tools become available (they may need to refresh the tool list).", connectURL)
		} else {
			text += " It needs your account connected before its tools can be used."
		}
	}
	return text
}

// requiresConfigMessage tells the caller which values the server needs before its
// tools work and how to supply them: plain values inline via `config` or through
// the hosted form, secrets only through the form. It names each variable and,
// when available, hands over the configure link for the user to open.
func requiresConfigMessage(res *appstore.InstallResult, configureURL string) string {
	var plain, secret []string
	for _, v := range res.ConfigVariables {
		if v.Secret {
			secret = append(secret, v.Name)
		} else {
			plain = append(plain, v.Name)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s needs some setup before its tools can be used.", res.Name)
	if len(plain) > 0 {
		fmt.Fprintf(&b, " It needs %s — ask the user, then either call install again with them in `config` (e.g. {\"code\":%q,\"config\":{%q:\"…\"}}) or have the user enter them at the link below.",
			strings.Join(plain, ", "), res.Code, plain[0])
	}
	if len(secret) > 0 {
		fmt.Fprintf(&b, " It needs a secret value (%s) that must be entered at the link below, never here.",
			strings.Join(secret, ", "))
	}
	if configureURL != "" {
		fmt.Fprintf(&b, " Configure it at %s — present this link to the user and let them decide whether to open it.", configureURL)
	}
	return b.String()
}

// buildConfigureURL builds the hosted configure-form URL for a ticket, mirroring
// buildConnectionURL but ending in /configure.
func buildConfigureURL(baseURL, consumerPath, ticket string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("%w: parse base url: %w", ErrStoreToolUnavailable, err)
	}
	base.Path = strings.TrimRight(consumerPath, "/") + "/configure"
	q := base.Query()
	q.Set("ticket", ticket)
	base.RawQuery = q.Encode()
	return base.String(), nil
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
			"text": searchSummary(query, category, total, matched),
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

func searchSummary(query, category string, total int, matched []storeSearchResult) string {
	var b strings.Builder
	returned := len(matched)
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
	// List each result's exact install code in the text body, not only in
	// structuredContent: many MCP clients surface only the text to the model, so
	// omitting the code here makes callers guess it (e.g. "linear" instead of
	// "app.linear/mcp"). trustgate_store_install takes this code verbatim.
	if returned > 0 {
		b.WriteString(" Install with the exact code:")
		for _, r := range matched {
			name := r.Name
			if name == "" {
				name = r.Code
			}
			fmt.Fprintf(&b, "\n• %s — code \"%s\" (%s)", name, r.Code, r.StoreState)
		}
	}
	return b.String()
}

func storeSearchDefinition() (Tool, error) {
	raw, err := json.Marshal(map[string]any{
		"name":        StoreSearchToolName,
		"title":       "Search the MCP catalog",
		"description": "Search the whole NeuralTrust MCP catalog for servers to install (not just the ones already installed). Call this whenever the user needs an integration or capability that is not available in the current tools — this gateway is the governed way to add MCP servers, so look here first and install through it (see " + StoreInstallToolName + ") rather than suggesting the user wire an MCP server into their client or connect to an upstream MCP URL directly, which bypasses the gateway. Search by name, vendor, category or capability. Returns catalog entries with their code, which INSTALL takes.",
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
	raw, err := json.Marshal(map[string]any{
		"name":  StoreInstallToolName,
		"title": "Install an MCP server",
		"description": "Install a catalog MCP server for the current user so its tools appear on this Store. When the user needs a server's capabilities, call this yourself to add it through the gateway — do not ask the user to install it manually, add it in their client's MCP settings, or connect to the upstream MCP URL directly, since that bypasses this gateway's governance, auditing and credentials. Takes the catalog `code` returned by " + StoreSearchToolName + ". " +
			"Some servers need per-user setup values (e.g. a Snowflake account URL, a ServiceNow instance): if so, this returns requires_config with the list of variables to collect — ask the user for them and call install again with them in `config`, or hand them the returned configure_url. " +
			"Governed by the user's role; a server that needs the user's own account returns a connect link for them to authorize before its tools work.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"code": map[string]any{
					"type":        "string",
					"description": "Catalog code of the MCP server.",
				},
				"config": map[string]any{
					"type":                 "object",
					"description":          "Per-user setup values for servers that declare them (from a prior requires_config response), e.g. {\"instance\":\"acme\"}. Non-secret values only; secrets are entered through the connect link.",
					"additionalProperties": map[string]any{"type": "string"},
				},
			},
			"required":             []string{"code"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    false,
			"destructiveHint": false,
			"idempotentHint":  false,
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
