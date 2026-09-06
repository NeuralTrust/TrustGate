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
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
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
	CreateTicket(ctx context.Context, in appoauth.ConfigureTicketRequest) (string, error)
}

// ServerConnectGateway mints a connect ticket scoped to one catalog server, so
// the install's OAuth connect link opens the focused single-server connect page.
// appoauth.ConnectService satisfies it. instanceID pins the ticket to the exact
// installation instance the install recorded ("" when none was).
type ServerConnectGateway interface {
	CreateServerTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath, code, instanceID string) (string, error)
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
	mode := t.effectiveStoreMode(ctx)
	if mode == gatewaydomain.StoreModeNone {
		return nil, fmt.Errorf("%w: self-service install is disabled for this gateway", ErrStoreToolUnavailable)
	}
	res, err := t.installer.Install(ctx, appstore.InstallRequest{
		GatewayID:    rc.Consumer.GatewayID,
		PrincipalSub: principal.Subject,
		Code:         args.Code,
		InstalledBy:  principal.Subject,
		Groups:       principalGroups(principal),
		OpenMode:     mode == gatewaydomain.StoreModeOpen,
		Config:       args.Config,
	})
	if err != nil {
		return nil, err
	}
	// A server that needs per-user setup gets a hosted-form link the user opens to
	// enter their values (the only path for secrets, and a nicer one for the rest).
	// The link is pinned to the instance this install recorded (if any) so the
	// form writes to that exact instance.
	configureURL := ""
	if res.RequiresConfig {
		configureURL = t.configureLink(ctx, rc, baseURL, res.Code, res.InstanceID, principal)
	}
	// A server that needs the user's own account gets the OAuth connect link right
	// in the install result — the second step of the install, so the user does not
	// have to hunt for it in their client. Offered even when the server was already
	// installed: "installed" is not "connected", so a re-install of an unconnected
	// server must still surface the link. Not offered when nothing was installed
	// (an admin must connect the server first).
	connectURL := ""
	if res.RequiresAuth && !res.RequiresAdminSetup {
		connectURL = t.connectLink(ctx, rc, baseURL, res.Code, res.InstanceID)
	}
	structured := map[string]any{
		"code":                 res.Code,
		"name":                 res.Name,
		"status":               string(res.Status),
		"pending":              res.Pending,
		"requires_auth":        res.RequiresAuth,
		"already_installed":    res.AlreadyInstalled,
		"requires_config":      res.RequiresConfig,
		"requires_admin_setup": res.RequiresAdminSetup,
		"config_variables":     configVariablesJSON(res.ConfigVariables),
	}
	if res.InstanceID != "" {
		structured["instance"] = res.InstanceID
	}
	if configureURL != "" {
		structured["configure_url"] = configureURL
		structured["configure_label"] = "Configure " + res.Name
	}
	if connectURL != "" {
		structured["connect_url"] = connectURL
		structured["connect_label"] = "Connect " + res.Name
	}
	return marshalToolResult(installMessage(res, configureURL, connectURL), structured)
}

// linkMarkdown renders a URL as a labeled markdown link so the client shows the
// label (e.g. "Connect Linear") rather than the raw URL.
func linkMarkdown(label, url string) string {
	return "[" + label + "](" + url + ")"
}

// connectLink mints an OAuth connect ticket and builds the hosted connect-page
// URL, or "" when no connect gateway is wired. Non-fatal on failure: the install
// still stands and the user can connect later.
func (t *storeTool) connectLink(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	baseURL, code, instanceID string,
) string {
	if t.connect == nil || strings.TrimSpace(baseURL) == "" {
		return ""
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return ""
	}
	consumerPath := appconsumer.MCPPath(rc.Consumer.Slug)
	ticket, err := t.connect.CreateServerTicket(ctx, rc.Consumer.GatewayID, principal.Subject, consumerPath, code, instanceID)
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
	baseURL, code, instanceID string,
	principal *identity.Principal,
) string {
	if t.configure == nil || strings.TrimSpace(baseURL) == "" {
		return ""
	}
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return ""
	}
	consumerPath := appconsumer.MCPPath(rc.Consumer.Slug)
	ticket, err := t.configure.CreateTicket(ctx, appoauth.ConfigureTicketRequest{
		GatewayID:    rc.Consumer.GatewayID,
		PrincipalSub: principal.Subject,
		ConsumerPath: consumerPath,
		Code:         code,
		InstanceID:   instanceID,
		Groups:       principalGroups(principal),
	})
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

// storeUninstallArgs is the uninstall meta-tool's input: the catalog code and,
// when the principal holds several instances of it, the instance id to remove.
type storeUninstallArgs struct {
	Code     string `json:"code"`
	Instance string `json:"instance,omitempty"`
}

func (t *storeTool) uninstall(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	arguments json.RawMessage,
) (json.RawMessage, error) {
	if t.installer == nil {
		return nil, fmt.Errorf("%w: uninstall is not available here", ErrStoreToolUnavailable)
	}
	var args storeUninstallArgs
	if err := json.Unmarshal(arguments, &args); err != nil || strings.TrimSpace(args.Code) == "" {
		return nil, fmt.Errorf("%w: uninstall requires a catalog code", ErrStoreToolUnavailable)
	}
	code := strings.TrimSpace(args.Code)
	sub, err := t.principalSubject(ctx)
	if err != nil {
		return nil, err
	}
	err = t.installer.Uninstall(ctx, rc.Consumer.GatewayID, sub, code, args.Instance)
	if errors.Is(err, appstore.ErrAmbiguousInstance) {
		// Several instances of this code are installed; hand back the list so the
		// caller can re-issue uninstall with the chosen instance id.
		return t.instancePicker(ctx, rc, code, "uninstall")
	}
	if err != nil {
		return nil, err
	}
	return marshalToolResult(
		fmt.Sprintf("Uninstalled %s.", code),
		map[string]any{"code": code, "uninstalled": true},
	)
}

// instancePicker returns a structured "which instance?" result listing the
// principal's active instances of a code (id + label), for an operation that
// must target one of several. It is a normal (non-error) result: the caller
// re-issues the operation with the chosen instance id.
func (t *storeTool) instancePicker(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	code, action string,
) (json.RawMessage, error) {
	sub, err := t.principalSubject(ctx)
	if err != nil {
		return nil, err
	}
	instances, err := t.installer.Instances(ctx, rc.Consumer.GatewayID, sub, code)
	if err != nil {
		return nil, err
	}
	list := make([]map[string]any, 0, len(instances))
	var b strings.Builder
	fmt.Fprintf(&b, "%s has several instances installed. Re-run %s with the `instance` id of the one you mean:", code, action)
	for _, in := range instances {
		label := in.InstanceLabel()
		if label == "" {
			label = code
		}
		list = append(list, map[string]any{"instance": in.ID.String(), "label": label})
		fmt.Fprintf(&b, "\n• %s — instance \"%s\"", label, in.ID.String())
	}
	return marshalToolResult(b.String(), map[string]any{
		"code":      code,
		"ambiguous": true,
		"instances": list,
	})
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
		text := fmt.Sprintf("%s was already installed.", res.Name)
		if res.RequiresAuth && connectURL != "" {
			text += fmt.Sprintf(" If its tools aren't working yet, present this link to the user to connect their account: %s", linkMarkdown("Connect "+res.Name, connectURL))
		}
		return text
	}
	if res.RequiresAdminSetup {
		return fmt.Sprintf("%s cannot be installed by users yet: it needs a credential only an administrator can add (a shared API key or a pre-registered OAuth client). Ask an admin to connect %s on this gateway's registry with that credential; once it is on the shelf, run install again.", res.Name, res.Name)
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
			// user authorizes their account. Present it as a labeled link, not a raw
			// URL, so the user sees "Connect <server>".
			text += fmt.Sprintf(" To finish, present this link to the user to connect their account: %s. Once they authorize, its tools become available (they may need to refresh the tool list).", linkMarkdown("Connect "+res.Name, connectURL))
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
		fmt.Fprintf(&b, " Present this link to the user to enter the values: %s.", linkMarkdown("Configure "+res.Name, configureURL))
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
	storeStateRequest   = "request"
)

// shelfEntry is one instance's Store grant: the groups/users it is granted to.
// Grants are explicit — both empty means granted to nobody (under Selected).
type shelfEntry struct {
	groups []string
	users  []string
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
	mode := t.effectiveStoreMode(ctx)
	principal := identity.PrincipalFromContext(ctx)
	groups := principalGroups(principal)
	subject := ""
	if principal != nil {
		subject = principal.Subject
	}
	// None closes the Store: nothing in the catalog is browsable.
	if mode == gatewaydomain.StoreModeNone {
		structured := map[string]any{
			"results":   []storeSearchResult{},
			"total":     0,
			"returned":  0,
			"truncated": false,
			"mode":      mode,
		}
		result := map[string]any{
			"content": []map[string]string{{
				"type": "text",
				"text": "The MCP Store is closed for this gateway; no servers are available to browse or install.",
			}},
			"structuredContent": structured,
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("%w: encode result: %w", ErrStoreToolUnavailable, err)
		}
		return raw, nil
	}

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
		// The whole catalog is browsable in All and Selected; the state tells the
		// caller whether install is instant for them or files a request.
		state := shelfState(shelf, entry.Code, mode, groups, subject)
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
			groups: reg.MCPTarget.StoreGroups(),
			users:  reg.MCPTarget.StoreUsers(),
		}
	}
	return shelf
}

// storeMode is the gateway's own Store mode. It fails closed: when no gateway
// resolved into the context there is nothing to say the Store may materialise
// arbitrary catalog servers, so the answer is curated (shelf-only), never open.
func (t *storeTool) storeMode(ctx context.Context) string {
	if gw, ok := appgateway.FromContext(ctx); ok && gw != nil {
		return gw.StoreMode()
	}
	return gatewaydomain.StoreModeCurated
}

// effectiveStoreMode is the Store mode that applies to the calling principal.
//
// On a self-service gateway (every non-enterprise tier) governance does not
// exist: the Store is always open and any per-principal store_access claim is
// ignored — no token can close or curate a self-service Store.
//
// On an enterprise gateway the principal's per-principal access claim
// (open/curated/none), when the control plane minted one, is the admin's
// explicit decision for that user/group and overrides the gateway default in
// both directions (it can open the Store for one user when the default is
// curated, or close it for one user when the default is open). An absent or
// unrecognised claim falls back to the gateway default, keeping tokens minted
// before this claim existed on their current behaviour. With no gateway in the
// context the tier is unknown, so the claim is honoured and the default fails
// closed (curated).
func (t *storeTool) effectiveStoreMode(ctx context.Context) string {
	return appstore.EffectiveStoreMode(ctx)
}

const storeShelfPageSize = 500

// shelfState is what installing this server means for the calling principal:
// "available" when it installs instantly — always under All, or under Selected
// when an instance exists and is granted to them — and "request" when the
// install would file an approval request instead.
func shelfState(shelf map[string]shelfEntry, code, mode string, groups []string, subject string) string {
	if mode == gatewaydomain.StoreModeOpen {
		return storeStateAvailable
	}
	entry, ok := shelf[code]
	if !ok {
		return storeStateRequest
	}
	if appstore.StoreAccessAllows(entry.groups, entry.users, groups, subject) {
		return storeStateAvailable
	}
	return storeStateRequest
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
	raw, err := json.Marshal(map[string]any{
		"name":  StoreUninstallToolName,
		"title": "Uninstall an MCP server",
		"description": "Remove a catalog MCP server the current user installed, taking its tools off this Store. Takes the catalog `code`. " +
			"When the user has several instances of that server (e.g. two Snowflake schemas), this returns an `instances` list with an id and label for each — re-run with the chosen `instance` id to remove just that one.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"code": map[string]any{
					"type":        "string",
					"description": "Catalog code of the MCP server.",
				},
				"instance": map[string]any{
					"type":        "string",
					"description": "Instance id to remove when several instances of the code are installed (from a prior ambiguous response). Omit when only one is installed.",
				},
			},
			"required":             []string{"code"},
			"additionalProperties": false,
		},
		"annotations": map[string]any{
			"readOnlyHint":    false,
			"destructiveHint": true,
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
