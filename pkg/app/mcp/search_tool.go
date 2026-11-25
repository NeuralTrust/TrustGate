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
	"fmt"
	"strconv"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

// trustgate_search.
//
// Everything it answers is read off the same composition tools/list and
// tools/call use — the inventory, which reads the discovery cache through the
// consumer's toolkit — so it cannot offer a tool the caller could not call,
// nor hide one they could. Ranking happens per request over that answer; there
// is no separate index to fall out of step with it.

const (
	defaultSearchLimit  = 10
	defaultListingLimit = 50
	maxSearchLimit      = 50
	// maxMixedStoreResults is how many catalog servers and agents a search on
	// the Store adds below the user's own tools.
	maxMixedStoreResults = 5
)

type searchArgs struct {
	Query    string `json:"query"`
	Kind     string `json:"kind"`
	Server   string `json:"server"`
	Category string `json:"category"`
	Name     string `json:"name"`
	Brief    bool   `json:"brief"`
	Limit    int    `json:"limit"`
	Cursor   string `json:"cursor"`
}

// toolCandidate is one tool the caller has, callable now or waiting on its
// server.
type toolCandidate struct {
	entry  InventoryEntry
	server InventoryServer
}

// searchKinds are the kinds this consumer can search, in the order they are
// offered.
func (d *RPCDispatcher) searchKinds(ctx context.Context, rc *appconsumer.RoutableConsumer) []string {
	kinds := []string{SearchKindOverview, SearchKindTool}
	if !isStore(rc) {
		return kinds
	}
	if d.store != nil {
		kinds = append(kinds, SearchKindCatalog)
	}
	if d.agents != nil {
		kinds = append(kinds, SearchKindAgent)
	}
	if d.storeOffers(ctx, rc, StoreModelsToolName) {
		kinds = append(kinds, SearchKindModel)
	}
	return kinds
}

func isStore(rc *appconsumer.RoutableConsumer) bool {
	return rc != nil && rc.Consumer != nil && consumerdomain.IsStoreConsumer(rc.Consumer)
}

// storeOffers reports whether the Store tool is wired with the dependencies
// one of its tools needs, which is when it lists that tool.
func (d *RPCDispatcher) storeOffers(ctx context.Context, rc *appconsumer.RoutableConsumer, name string) bool {
	if d.store == nil || !isStore(rc) {
		return false
	}
	for _, def := range d.store.Definitions(ctx, rc) {
		if def.Name == name {
			return true
		}
	}
	return false
}

func (d *RPCDispatcher) search(ctx context.Context, req dispatchRequest, arguments json.RawMessage) (any, error) {
	markMetaTool(ctx)
	if d.inventoryImpl == nil || !metaToolsPermitted(req.consumer) {
		return nil, &ToolNotPermittedError{Tool: SearchToolName}
	}
	var args searchArgs
	if len(arguments) > 0 {
		if err := json.Unmarshal(arguments, &args); err != nil {
			d.searchStats.searched(ctx, req.consumer, searchKindUnknown, searchResultInvalid)
			return toolErrorResult(
				SearchToolName+" takes {\"query\", \"kind\", \"server\", \"name\", \"limit\", \"cursor\"}, all optional, and these arguments could not be read as that. Fix them and call again.",
				map[string]any{"error": "invalid_arguments"},
			)
		}
	}
	args.Query = strings.TrimSpace(args.Query)
	args.Kind = strings.ToLower(strings.TrimSpace(args.Kind))
	args.Server = strings.TrimSpace(args.Server)
	args.Name = strings.TrimSpace(args.Name)

	kinds := d.searchKinds(ctx, req.consumer)
	if args.Kind != "" && !containsString(kinds, args.Kind) {
		d.searchStats.searched(ctx, req.consumer, searchKindUnknown, searchResultInvalid)
		return toolErrorResult(
			fmt.Sprintf("%s cannot search %q here. It searches: %s.", SearchToolName, args.Kind, strings.Join(kinds, ", ")),
			map[string]any{"error": "invalid_arguments", "kinds": kinds},
		)
	}

	switch args.Kind {
	case SearchKindCatalog, SearchKindAgent, SearchKindModel:
		d.searchStats.searched(ctx, req.consumer, args.Kind, searchResultAnswered)
	}
	switch args.Kind {
	case SearchKindCatalog:
		return d.delegateSearch(ctx, req, StoreSearchToolName, map[string]any{
			"query": args.Query, "category": args.Category, "limit": args.Limit,
		})
	case SearchKindAgent:
		raw, err := json.Marshal(map[string]any{"query": args.Query})
		if err != nil {
			return nil, err
		}
		result, err := d.agents.Call(ctx, ListAgentsToolName, raw)
		if err != nil {
			return consolidatedToolError(err)
		}
		return withConsolidatedText(result), nil
	case SearchKindModel:
		return d.delegateSearch(ctx, req, StoreModelsToolName, map[string]any{})
	}

	inventory, err := d.inventoryImpl.surface.ToolInventory(ctx, req.consumer)
	if err != nil {
		return nil, err
	}
	if args.Name != "" {
		result, found, err := d.describeTool(inventory, args.Name, isStore(req.consumer))
		outcome := searchResultNotFound
		if found {
			outcome = searchResultFound
		}
		d.searchStats.searched(ctx, req.consumer, searchKindDetail, outcome)
		return result, err
	}
	if args.Kind == SearchKindOverview || (args.Kind == "" && args.Query == "" && args.Server == "") {
		d.searchStats.searched(ctx, req.consumer, SearchKindOverview, searchResultAnswered)
		return d.overview(ctx, req.consumer, inventory, strings.ToLower(args.Server), args.Brief)
	}
	return d.searchTools(ctx, req, inventory, args)
}

func (d *RPCDispatcher) delegateSearch(ctx context.Context, req dispatchRequest, tool string, fields map[string]any) (any, error) {
	for key, value := range fields {
		switch v := value.(type) {
		case string:
			if v == "" {
				delete(fields, key)
			}
		case int:
			if v <= 0 {
				delete(fields, key)
			}
		}
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	result, err := d.store.Call(ctx, req.consumer, req.baseURL, tool, raw)
	if err != nil {
		return consolidatedToolError(err)
	}
	return withConsolidatedText(result), nil
}

// candidates are every tool on the caller's surface: the ones their servers
// serve, and the ones a server waiting on a connection, or unreachable, would
// serve once it answers, from the catalog's snapshot of it.
func (d *RPCDispatcher) candidates(inventory *ToolInventory, serverFilter string) []toolCandidate {
	previews := d.inventoryImpl.catalogTools()
	var out []toolCandidate
	for _, server := range inventory.Servers {
		if !matchesServerFilter(server, serverFilter) {
			continue
		}
		if len(server.Tools) > 0 {
			for _, entry := range server.Tools {
				out = append(out, toolCandidate{entry: entry, server: server})
			}
			continue
		}
		if !notServing(server.State) {
			continue
		}
		for _, entry := range pendingTools(previews, server) {
			out = append(out, toolCandidate{entry: entry, server: server})
		}
	}
	return out
}

// pendingTools names a server's catalog snapshot the way tools/call will name
// its tools once it serves them, trimmed to what the consumer's toolkit
// permits.
func pendingTools(previews map[string][]catalogdomain.MCPTool, server InventoryServer) []InventoryEntry {
	if server.Code == "" || server.serverSlug == "" || len(previews) == 0 {
		return nil
	}
	snapshot, ok := previews[server.Code]
	if !ok {
		return nil
	}
	out := make([]InventoryEntry, 0, len(snapshot))
	for _, tool := range snapshot {
		if !server.Permits(tool.Name) {
			continue
		}
		out = append(out, InventoryEntry{
			Name:        exposedName{name: tool.Name, server: server.serverSlug}.String(),
			Description: tool.Description,
		})
	}
	return out
}

func (d *RPCDispatcher) searchTools(ctx context.Context, req dispatchRequest, inventory *ToolInventory, args searchArgs) (any, error) {
	candidates := d.candidates(inventory, strings.ToLower(args.Server))
	limit := args.Limit
	if limit <= 0 {
		limit = defaultSearchLimit
		if args.Query == "" {
			limit = defaultListingLimit
		}
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}
	offset := 0
	if args.Cursor != "" {
		n, err := strconv.Atoi(args.Cursor)
		if err != nil || n < 0 {
			return toolErrorResult("That cursor is not one this tool gave. Search again without it.", map[string]any{"error": "invalid_arguments"})
		}
		offset = n
	}

	ordered := make([]int, 0, len(candidates))
	match := "listing"
	if args.Query == "" {
		for i := range candidates {
			ordered = append(ordered, i)
		}
	} else {
		docs := make([]searchDoc, len(candidates))
		for i, c := range candidates {
			docs[i] = searchDoc{
				Name:        c.entry.Name,
				Title:       c.entry.Title,
				Server:      c.server.Name,
				Code:        c.server.Code,
				Description: c.entry.Description,
				Params:      schemaParamNames(c.entry.InputSchema),
			}
		}
		ranked := rankSearchDocs(args.Query, docs)
		match = "ranked"
		if len(ranked) == 0 {
			ranked = substringMatches(args.Query, docs)
			match = "substring"
		}
		for _, r := range ranked {
			ordered = append(ordered, r.Index)
		}
	}

	total := len(ordered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	results := make([]map[string]any, 0, end-offset)
	for _, i := range ordered[offset:end] {
		results = append(results, searchResultJSON(candidates[i], args.Brief))
	}
	structured := map[string]any{
		"kind":     SearchKindTool,
		"results":  results,
		"total":    total,
		"returned": len(results),
		"match":    match,
	}
	if args.Query != "" {
		structured["query"] = args.Query
	}
	if end < total {
		structured["next_cursor"] = strconv.Itoa(end)
	}

	var catalog, agents []map[string]any
	if args.Query != "" && offset == 0 && isStore(req.consumer) && args.Kind == "" {
		catalog = d.catalogMatches(ctx, req, args.Query)
		agents = d.agentMatches(ctx, args.Query)
		if len(catalog) > 0 {
			structured["catalog"] = catalog
		}
		if len(agents) > 0 {
			structured["agents"] = agents
		}
	}
	if args.Query != "" {
		names := make([]string, 0, end-offset)
		for _, i := range ordered[offset:end] {
			names = append(names, candidates[i].entry.Name)
		}
		d.searchStats.searchedTools(ctx, req.consumer, match, total, len(catalog) > 0 || len(agents) > 0, names, offset)
	} else {
		d.searchStats.searchedTools(ctx, req.consumer, match, total, false, nil, offset)
	}
	if total == 0 && len(catalog) == 0 && len(agents) == 0 {
		// Nothing matched. The answer is never just "nothing": it names what
		// the user does have, so the caller can look there instead.
		structured["servers"] = overviewServers(inventory, isStore(req.consumer))
	}
	return marshalToolResult(searchToolsText(ctx, args, results, total, end < total, catalog, agents, inventory), structured)
}

func searchResultJSON(c toolCandidate, brief bool) map[string]any {
	out := map[string]any{
		"name":     c.entry.Name,
		"server":   c.server.Name,
		"state":    c.server.State,
		"callable": c.entry.Callable,
	}
	if c.server.Code != "" {
		out["code"] = c.server.Code
	}
	if c.entry.Risk != "" {
		out["risk"] = c.entry.Risk
	}
	if brief {
		return out
	}
	if title := strings.TrimSpace(c.entry.Title); title != "" {
		out["title"] = title
	}
	if desc := truncateDescription(c.entry.Description); desc != "" {
		out["description"] = desc
	}
	if c.entry.Callable {
		out["signature"] = toolSignature(c.entry.Name, c.entry.InputSchema, c.entry.OutputSchema)
	}
	return out
}

func (d *RPCDispatcher) catalogMatches(ctx context.Context, req dispatchRequest, query string) []map[string]any {
	if d.store == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]any{"query": query, "limit": maxMixedStoreResults})
	if err != nil {
		return nil
	}
	result, err := d.store.Call(ctx, req.consumer, req.baseURL, StoreSearchToolName, raw)
	if err != nil {
		return nil
	}
	isError, structured, ok := structuredOf(result)
	if !ok || isError || structured == nil {
		return nil
	}
	items, _ := structured["results"].([]any)
	var out []map[string]any
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		// What the user already installed is on their surface, and the tool
		// results above already answer for it.
		if state, _ := entry["store_state"].(string); state == "installed" {
			continue
		}
		code, _ := entry["code"].(string)
		listed := map[string]any{
			"code":        code,
			"name":        entry["name"],
			"store_state": entry["store_state"],
		}
		if code != "" {
			listed["next"] = map[string]any{
				"tool":      AccessToolName,
				"arguments": map[string]any{"action": AccessActionInstall, "target": code},
			}
		}
		out = append(out, listed)
	}
	return out
}

func (d *RPCDispatcher) agentMatches(ctx context.Context, query string) []map[string]any {
	if d.agents == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]any{"query": query})
	if err != nil {
		return nil
	}
	result, err := d.agents.Call(ctx, ListAgentsToolName, raw)
	if err != nil {
		return nil
	}
	isError, structured, ok := structuredOf(result)
	if !ok || isError || structured == nil {
		return nil
	}
	items, _ := structured["agents"].([]any)
	var out []map[string]any
	for _, item := range items {
		if len(out) == maxMixedStoreResults {
			break
		}
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, map[string]any{
			"id":          entry["id"],
			"name":        entry["name"],
			"description": entry["description"],
		})
	}
	return out
}

func searchToolsText(
	ctx context.Context,
	args searchArgs,
	results []map[string]any,
	total int,
	more bool,
	catalog, agents []map[string]any,
	inventory *ToolInventory,
) string {
	var b strings.Builder
	switch {
	case total == 0 && args.Query != "":
		fmt.Fprintf(&b, "No tool on the user's surface matches %q.", args.Query)
	case total == 0:
		b.WriteString("No tools on the user's surface")
		if args.Server != "" {
			fmt.Fprintf(&b, " on a server matching %q", args.Server)
		}
		b.WriteString(".")
	case args.Query != "":
		fmt.Fprintf(&b, "%d tool(s) match %q, best first", total, args.Query)
		if more {
			fmt.Fprintf(&b, " (showing %d)", len(results))
		}
		b.WriteString(":")
	default:
		fmt.Fprintf(&b, "%d tool(s)", total)
		if more {
			fmt.Fprintf(&b, " (showing %d)", len(results))
		}
		b.WriteString(":")
	}
	for _, r := range results {
		name, _ := r["name"].(string)
		server, _ := r["server"].(string)
		fmt.Fprintf(&b, "\n\n• %s — on %s", name, server)
		var notes []string
		if callable, _ := r["callable"].(bool); !callable {
			notes = append(notes, "not callable yet: its server is "+displayString(r["state"]))
		}
		if risk, _ := r["risk"].(string); risk != "" {
			notes = append(notes, strings.ReplaceAll(risk, "_", "-"))
		}
		if len(notes) > 0 {
			fmt.Fprintf(&b, " (%s)", strings.Join(notes, ", "))
		}
		if desc, _ := r["description"].(string); desc != "" {
			fmt.Fprintf(&b, "\n  %s", desc)
		}
		if sig, _ := r["signature"].(string); sig != "" {
			fmt.Fprintf(&b, "\n  %s", sig)
		}
	}
	if more {
		b.WriteString("\n\nMore results: call again with the next_cursor.")
	}
	if len(catalog) > 0 {
		b.WriteString("\n\nNot installed yet, in the Store (install with " + AccessToolName + " {\"action\": \"install\", \"target\": <code>}):")
		for _, entry := range catalog {
			fmt.Fprintf(&b, "\n• %s (%s)", displayString(entry["name"]), displayString(entry["code"]))
		}
	}
	if len(agents) > 0 {
		b.WriteString("\n\nThe user's agents that match (call one with " + GatewayCallToolName + " {\"agent\": <id>, \"message\": …}):")
		for _, entry := range agents {
			fmt.Fprintf(&b, "\n• %s (%s)", displayString(entry["name"]), displayString(entry["id"]))
		}
	}
	if total == 0 && len(catalog) == 0 && len(agents) == 0 {
		if len(inventory.Servers) == 0 {
			b.WriteString(" The user has no MCP servers on their surface.")
		} else {
			b.WriteString(" These are the user's servers; list one's tools with " + SearchToolName + " {\"kind\": \"tool\", \"server\": <name>}:")
			for _, server := range inventory.Servers {
				fmt.Fprintf(&b, "\n• %s — %s", server.Name, server.State)
			}
		}
	} else if total > 0 {
		b.WriteString("\n\nCall a tool directly if it is in your tool list, otherwise with " + GatewayCallToolName + " {\"tool\": <name>, \"arguments\": {…}}. " +
			SearchToolName + " {\"name\": <name>} gives one tool's full description and input schema.")
		if hint := programHint(ctx); hint != "" {
			b.WriteString(" " + hint)
		}
	}
	return b.String()
}

// programHint is the sentence a search answer closes with when the gateway
// runs Code Mode programs: the signatures above are the API a program calls.
func programHint(ctx context.Context) string {
	query, execute := CodeModeOffered(ctx)
	switch {
	case execute:
		return "To do several calls at once, write them in one " + QueryToolName + " (reads only) or " + ExecuteToolName + " program, calling each as await tools.<name>({…}) with the signatures above."
	case query:
		return "To do several read calls at once, write them in one " + QueryToolName + " program, calling each as await tools.<name>({…}) with the signatures above."
	}
	return ""
}

// overviewServers are the caller's servers as the overview lists them:
// state, why one is not serving, how many tools, and what fixes it.
func overviewServers(inventory *ToolInventory, store bool) []map[string]any {
	out := make([]map[string]any, 0, len(inventory.Servers))
	for _, server := range inventory.Servers {
		entry := map[string]any{
			"name":       server.Name,
			"state":      server.State,
			"tool_count": len(server.Tools),
		}
		if server.Code != "" {
			entry["code"] = server.Code
		}
		if server.Cause != "" {
			entry["cause"] = server.Cause
		}
		if len(server.Denied) > 0 {
			entry["denied_tools"] = server.Denied
		}
		if next := nextForServer(server, store); next != nil {
			entry["next"] = next
		}
		out = append(out, entry)
	}
	return out
}

// nextForServer is the call that fixes a server the caller can fix
// themselves: connecting the account it waits on.
func nextForServer(server InventoryServer, store bool) map[string]any {
	if server.State != InventoryStateNeedsConnect || server.Provider == "" || callerCannotConnect(server.Cause) {
		return nil
	}
	target := server.Provider
	if store {
		if server.Code == "" {
			return nil
		}
		target = server.Code
	}
	return map[string]any{
		"tool":      AccessToolName,
		"arguments": map[string]any{"action": AccessActionConnect, "target": target},
	}
}

func (d *RPCDispatcher) overview(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	inventory *ToolInventory,
	filter string,
	brief bool,
) (any, error) {
	store := isStore(rc)
	previews := d.inventoryImpl.catalogTools()
	servers := make([]map[string]any, 0, len(inventory.Servers))
	callable, pending := 0, 0
	for _, server := range inventory.Servers {
		if !matchesServerFilter(server, filter) {
			continue
		}
		entry := map[string]any{
			"name":  server.Name,
			"state": server.State,
		}
		if server.Code != "" {
			entry["code"] = server.Code
		}
		if server.Cause != "" {
			entry["cause"] = server.Cause
		}
		count := len(server.Tools)
		callable += count
		if count == 0 && notServing(server.State) {
			count = len(pendingTools(previews, server))
			pending += count
		}
		entry["tool_count"] = count
		if len(server.Denied) > 0 {
			entry["denied_tools"] = server.Denied
		}
		if next := nextForServer(server, store); next != nil {
			entry["next"] = next
		}
		servers = append(servers, entry)
	}
	structured := map[string]any{
		"kind":           SearchKindOverview,
		"servers":        servers,
		"total_servers":  len(servers),
		"callable_tools": callable,
		"pending_tools":  pending,
	}
	var installable []map[string]any
	storeMode := ""
	if store {
		installable, storeMode = d.inventoryImpl.installable(ctx, rc, servers, filter)
		for _, entry := range installable {
			delete(entry, "install_tool")
			if brief {
				delete(entry, "description")
			}
			entry["next"] = map[string]any{
				"tool":      AccessToolName,
				"arguments": map[string]any{"action": AccessActionInstall, "target": entry["code"]},
			}
		}
		if storeMode != "" {
			structured["store_mode"] = storeMode
		}
		if len(installable) > 0 {
			structured["installable"] = installable
		}
	}
	return marshalToolResult(overviewText(servers, callable, pending, filter, installable, storeMode, store), structured)
}

func overviewText(
	servers []map[string]any,
	callable, pending int,
	filter string,
	installable []map[string]any,
	storeMode string,
	store bool,
) string {
	var b strings.Builder
	if len(servers) == 0 {
		if filter != "" {
			fmt.Fprintf(&b, "No MCP server matching %q is on the user's surface.", filter)
		} else {
			b.WriteString("The user has no MCP servers on their surface.")
		}
	} else {
		fmt.Fprintf(&b, "The user has %d MCP server(s): %d tool(s) callable now", len(servers), callable)
		if pending > 0 {
			fmt.Fprintf(&b, " and %d more waiting on a server that is not ready", pending)
		}
		b.WriteString(".")
		for _, server := range servers {
			fmt.Fprintf(&b, "\n\n• %s", displayString(server["name"]))
			if code := displayString(server["code"]); code != "" {
				fmt.Fprintf(&b, " (%s)", code)
			}
			fmt.Fprintf(&b, " — %s", overviewStateText(server))
		}
	}
	if len(installable) > 0 {
		fmt.Fprintf(&b, "\n\nThe user can also add %d server(s) from the Store with %s {\"action\": \"install\", \"target\": <code>}:", len(installable), AccessToolName)
		for _, entry := range installable {
			fmt.Fprintf(&b, "\n• %s (%s)", displayString(entry["name"]), displayString(entry["code"]))
			if desc := displayString(entry["description"]); desc != "" {
				fmt.Fprintf(&b, " — %s", desc)
			}
		}
		b.WriteString("\nThose are not on their surface yet: offer to add one; none of its tools can be called until it is added.")
	} else if store && storeMode == "open" {
		fmt.Fprintf(&b, "\n\nThe Store is open to the user: %s {\"kind\": \"catalog\", \"query\": …} finds a server to add by name or purpose.", SearchToolName)
	}
	b.WriteString("\n\nFind a tool by what it does with " + SearchToolName + " {\"query\": …}, or list a server's tools with {\"kind\": \"tool\", \"server\": <name>}. " +
		"That is the whole list: the gateway's own trustgate_* tools manage this surface and are not tools the user has.")
	return b.String()
}

func overviewStateText(server map[string]any) string {
	count, _ := server["tool_count"].(int)
	switch displayString(server["state"]) {
	case InventoryStateReady:
		return fmt.Sprintf("ready, %d tool(s)", count)
	case InventoryStateNeedsConnect:
		switch displayString(server["cause"]) {
		case InventoryCauseSharedAccountNotConnected:
			return "not connected: it uses one shared account for every caller and nobody has connected it; an administrator connects it in the console"
		case InventoryCauseEndUserNotNamed:
			return "not connected: it keeps one account per person and this request named nobody; the application has to name the user it acts for"
		}
		text := fmt.Sprintf("not connected: its %d tool(s) cannot be called until the user connects their account", count)
		if next, ok := server["next"].(map[string]any); ok {
			args, _ := json.Marshal(next["arguments"])
			text += ", which " + AccessToolName + " " + string(args) + " gives them a link for"
		}
		if cause := displayString(server["cause"]); cause != "" {
			text += " (" + cause + ")"
		}
		return text
	case InventoryStateUnavailable:
		return "unavailable: " + unavailablePhrase(displayString(server["cause"])) + ", so its tools cannot be called right now"
	case InventoryStateNoTools:
		return "no tools available to this connection"
	default:
		return "unknown state"
	}
}

// describeTool answers a request for one tool by its exact name. A name that
// is not on the surface answers with the closest ones that are, so a caller
// holding a stale or misspelt name is one step from the right one.
// describeTool answers a lookup by name, and whether the name was found.
func (d *RPCDispatcher) describeTool(inventory *ToolInventory, name string, store bool) (any, bool, error) {
	candidates := d.candidates(inventory, "")
	for _, c := range candidates {
		if c.entry.Name != name {
			continue
		}
		structured := map[string]any{
			"name":     c.entry.Name,
			"found":    true,
			"server":   c.server.Name,
			"state":    c.server.State,
			"callable": c.entry.Callable,
		}
		if c.server.Code != "" {
			structured["code"] = c.server.Code
		}
		if c.entry.Risk != "" {
			structured["risk"] = c.entry.Risk
		}
		if title := strings.TrimSpace(c.entry.Title); title != "" {
			structured["title"] = title
		}
		if desc := strings.TrimSpace(c.entry.Description); desc != "" {
			structured["description"] = desc
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s (on %s)", c.entry.Name, c.server.Name)
		if title := strings.TrimSpace(c.entry.Title); title != "" {
			fmt.Fprintf(&b, " — %s", title)
		}
		if desc := strings.TrimSpace(c.entry.Description); desc != "" {
			fmt.Fprintf(&b, "\n\n%s", desc)
		}
		if !c.entry.Callable {
			fmt.Fprintf(&b, "\n\nIt cannot be called yet: %s %s. Its input schema is known once the server serves it.",
				c.server.Name, pendingServerPhrase(c.server, store))
			result, err := marshalToolResult(b.String(), structured)
			return result, true, err
		}
		schema := json.RawMessage(`{"type":"object"}`)
		if len(c.entry.InputSchema) > 0 && json.Valid(c.entry.InputSchema) {
			schema = c.entry.InputSchema
		}
		signature := toolSignature(c.entry.Name, c.entry.InputSchema, c.entry.OutputSchema)
		structured["input_schema"] = schema
		structured["signature"] = signature
		if len(c.entry.OutputSchema) > 0 && json.Valid(c.entry.OutputSchema) {
			structured["output_schema"] = c.entry.OutputSchema
		}
		structured["call_with"] = GatewayCallToolName
		if c.entry.Risk != "" {
			fmt.Fprintf(&b, "\n\nRisk: %s.", c.entry.Risk)
		}
		fmt.Fprintf(&b, "\n\nSignature: %s\n\nInput schema: %s", signature, schema)
		fmt.Fprintf(&b, "\n\nIf %s is not in your own tool list, call it with %s: {\"tool\": %q, \"arguments\": {…}}.", c.entry.Name, GatewayCallToolName, c.entry.Name)
		result, err := marshalToolResult(b.String(), structured)
		return result, true, err
	}

	docs := make([]searchDoc, len(candidates))
	for i, c := range candidates {
		docs[i] = searchDoc{Name: c.entry.Name, Title: c.entry.Title, Server: c.server.Name, Code: c.server.Code, Description: c.entry.Description}
	}
	var suggestions []string
	for _, r := range rankSearchDocs(name, docs) {
		if len(suggestions) == 5 {
			break
		}
		suggestions = append(suggestions, candidates[r.Index].entry.Name)
	}
	structured := map[string]any{"name": name, "found": false}
	text := fmt.Sprintf("No tool named %q is on the user's surface.", name)
	if len(suggestions) > 0 {
		structured["suggestions"] = suggestions
		text += " The closest are: " + strings.Join(suggestions, ", ") + "."
	} else {
		text += " Search for it with " + SearchToolName + " {\"query\": …}."
	}
	result, err := marshalToolResult(text, structured)
	return result, false, err
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// pendingServerPhrase says why a server that is not serving is not, and what
// fixes it when the caller can.
func pendingServerPhrase(server InventoryServer, store bool) string {
	switch server.State {
	case InventoryStateUnavailable:
		return "is unavailable: " + unavailablePhrase(server.Cause)
	case InventoryStateNeedsConnect:
		switch server.Cause {
		case InventoryCauseSharedAccountNotConnected:
			return "uses one shared account that nobody has connected; an administrator connects it in the console"
		case InventoryCauseEndUserNotNamed:
			return "keeps one account per person and this request named nobody"
		}
		phrase := "is waiting for the user to connect their account"
		if next := nextForServer(server, store); next != nil {
			args, _ := json.Marshal(next["arguments"])
			phrase += ", which " + AccessToolName + " " + string(args) + " gives them a link for"
		}
		return phrase
	default:
		return "is " + server.State
	}
}
