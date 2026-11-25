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
	"encoding/json"
	"strings"
)

// The consolidated gateway tools (see Surface).
const (
	// SearchToolName finds anything the user has or could get: their tools,
	// ready or waiting on a connection, and on the Store catalog servers,
	// agents and LLM models. It replaces InventoryToolName,
	// StoreSearchToolName, ListAgentsToolName and StoreModelsToolName.
	SearchToolName = "trustgate_search"
	// GatewayCallToolName calls one of the user's tools, or on the Store one of
	// their agents, by name. It replaces CallToolName and CallAgentToolName.
	GatewayCallToolName = "trustgate_call"
	// AccessToolName changes what the user has: connect an account, and on
	// the Store install or uninstall a server, open the personal-key page or
	// request models. It replaces the trustgate_connect_* tools and the
	// Store's install, uninstall, personal-key and request-models tools.
	AccessToolName = "trustgate_access"
)

// Kinds trustgate_search answers.
const (
	SearchKindOverview = "overview"
	SearchKindTool     = "tool"
	SearchKindCatalog  = "catalog"
	SearchKindAgent    = "agent"
	SearchKindModel    = "model"
)

// Actions trustgate_access takes.
const (
	AccessActionInstall   = "install"
	AccessActionUninstall = "uninstall"
	AccessActionConnect   = "connect"
	// AccessActionKey hands the user the page where they create, rotate or
	// revoke their personal key, the key their LLM models are called with.
	AccessActionKey     = "key"
	AccessActionRequest = "request"
)

// AccessTargetPersonalKey is the target that made a connect open the personal
// key page before AccessActionKey existed. It is still accepted.
const AccessTargetPersonalKey = "personal_key"

// consolidatedToolDisclaimer is GatewayToolDisclaimer for the consolidated
// surface, which answers "what do I have" with trustgate_search.
const consolidatedToolDisclaimer = " This is one of the gateway's own tools, not one of the user's: leave it out when telling the user which tools or servers they have (" +
	SearchToolName + " answers that)."

// IsConsolidatedToolName reports whether a name is one of the consolidated
// gateway tools.
func IsConsolidatedToolName(name string) bool {
	return name == SearchToolName || name == GatewayCallToolName || name == AccessToolName
}

func searchDefinition(kinds []string, store bool) (Tool, error) {
	description := "Find what the user can use through this gateway: their MCP tools, ready or waiting for a connection"
	if store {
		description += ", and the MCP servers they can add from the Store, their agents and their LLM models"
	}
	description += ". Call it with no arguments at the start of a conversation: it lists the user's servers, which of them need attention and why, and what fixes each one. " +
		"Pass `query` to search the user's tools by what they do (for example \"comment on a linear issue\"); the results give each tool's exact name, its arguments and whether it only reads or also writes. " +
		"Pass `name` to read one tool in full, with its input schema. Leave `query` out and pass `kind: \"tool\"` (optionally with `server`) to list every tool, page by page, when a search does not find what you need. " +
		"A tool from these results that is missing from your own tool list can be called with " + GatewayCallToolName + "."
	if store {
		description += " Use `kind: \"catalog\"` to search the Store for servers to install, `kind: \"agent\"` for the user's agents and `kind: \"model\"` for their LLM models."
	}
	description += consolidatedToolDisclaimer
	return toolFromDefinition(map[string]any{
		"name":        SearchToolName,
		"title":       "Find the user's tools",
		"description": description,
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "What to look for, in plain words. Omit it, with no kind, for the overview of the user's servers.",
				},
				"kind": map[string]any{
					"type":        "string",
					"enum":        kinds,
					"description": "What to search. overview: the user's servers and their state. tool: the user's tools.",
				},
				"server": map[string]any{
					"type":        "string",
					"description": "Only the servers whose name or catalog code contains this text.",
				},
				"category": map[string]any{
					"type":        "string",
					"description": "With kind catalog: only this catalog category.",
				},
				"name": map[string]any{
					"type":        "string",
					"description": "The exact name of one tool to describe in full, with its input schema.",
				},
				"brief": map[string]any{
					"type":        "boolean",
					"description": "Leave descriptions and signatures out.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"minimum":     1,
					"maximum":     maxSearchLimit,
					"description": "How many results per page (10 for a search, 50 for a listing).",
				},
				"cursor": map[string]any{
					"type":        "string",
					"description": "The next_cursor of a previous answer, for the next page.",
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
}

func gatewayCallDefinition(agents bool) (Tool, error) {
	description := "Call one of the user's tools through this gateway by its exact name, as " + SearchToolName + " gives it, with its arguments. " +
		"Use it when the tool is missing from your own tool list: your client may still show the list it had before a server was installed or connected. When the tool is in your list, call it directly instead. " +
		"If the tool refuses the arguments, the answer carries its input schema: fix them and call again. " +
		"The call runs exactly as a direct call would, with the same policies, approvals and audit, and returns the tool's own result."
	properties := map[string]any{
		"tool": map[string]any{
			"type":        "string",
			"description": "The tool's exact name, for example linear_save_issue.",
		},
		"arguments": map[string]any{
			"type":                 "object",
			"description":          "The tool's own arguments, matching its input schema. Omit for a tool that takes none.",
			"additionalProperties": true,
		},
	}
	if agents {
		description += " To send a message to one of the user's agents instead, pass `agent` and `message` (and the `context_id` of an earlier answer to continue that conversation), or `agent` and `task_id` to read a task an earlier answer named."
		properties["agent"] = map[string]any{
			"type":        "string",
			"description": "The agent's id, or its exact name, as " + SearchToolName + " {\"kind\": \"agent\"} lists it. Give either this or `tool`.",
		}
		properties["message"] = map[string]any{
			"type":        "string",
			"description": "With agent: the text to send.",
		}
		properties["context_id"] = map[string]any{
			"type":        "string",
			"description": "With agent: the context_id of an earlier answer, to continue that conversation.",
		}
		properties["task_id"] = map[string]any{
			"type":        "string",
			"description": "With agent: a task an earlier answer named, to read its current state.",
		}
	}
	description += consolidatedToolDisclaimer
	return toolFromDefinition(map[string]any{
		"name":        GatewayCallToolName,
		"title":       "Call one of the user's tools by name",
		"description": description,
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           properties,
			"additionalProperties": false,
		},
		// It can reach any of the user's tools, writes included, so a client
		// that asks before a write must ask here too.
		"annotations": map[string]any{
			"readOnlyHint":    false,
			"destructiveHint": true,
			"idempotentHint":  false,
			"openWorldHint":   true,
		},
	})
}

func accessDefinition(actions []string, store bool) (Tool, error) {
	description := "Change what the user has through this gateway."
	if store {
		var does []string
		for _, action := range actions {
			switch action {
			case AccessActionInstall:
				does = append(does, "install adds a server from the Store (target: its catalog code, from "+SearchToolName+")")
			case AccessActionUninstall:
				does = append(does, "uninstall removes one (target: its code)")
			case AccessActionConnect:
				does = append(does, "connect gives the user a link to connect the account a server is waiting on (target: the server's code)")
			case AccessActionKey:
				does = append(does, "key gives the user the page where they create, rotate or revoke their personal key, the key their LLM models are called with (no target): the key is shown to them there and never to you, so do not ask them for it")
			case AccessActionRequest:
				does = append(does, "request asks an administrator for access to an LLM provider's models (target: the provider)")
			}
		}
		description += " " + strings.Join(does, "; ") + "."
		if containsString(actions, AccessActionInstall) {
			description += " Install it yourself when the user needs a server: do not ask them to add an MCP server in their client or to connect to an upstream URL directly, which bypasses the gateway."
		}
	} else {
		description += " connect gives the user a link to connect the account one of their servers is waiting on (target: the server's name or provider, as " + SearchToolName + " names it)."
	}
	description += " When the answer carries a link, show it to the user as a link and let them decide whether to open it: never say it opened, and never write a reason or a secret for them."
	description += consolidatedToolDisclaimer
	properties := map[string]any{
		"action": map[string]any{
			"type": "string",
			"enum": actions,
		},
		"target": map[string]any{
			"type":        "string",
			"description": "What the action applies to. Every action but key needs one.",
		},
	}
	if store {
		properties["config"] = map[string]any{
			"type":                 "object",
			"description":          "With install: per-user setup values the server declares (from an earlier requires_config answer), e.g. {\"instance\":\"acme\"}. Never secrets: those go on the page the link opens.",
			"additionalProperties": map[string]any{"type": "string"},
		}
		properties["registry_id"] = map[string]any{
			"type":        "string",
			"description": "With install: the instance to install, from an earlier choose_instance answer. With request: the provider registry, from an earlier choose_registry answer.",
		}
		properties["installation_id"] = map[string]any{
			"type":        "string",
			"description": "With uninstall: the installation to remove, from an earlier choose_installation answer.",
		}
	}
	return toolFromDefinition(map[string]any{
		"name":        AccessToolName,
		"title":       "Change what the user has",
		"description": description,
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           properties,
			"required":             []string{"action"},
			"additionalProperties": false,
		},
		// uninstall removes what the user had, so a client that asks before a
		// destructive call must ask here.
		"annotations": map[string]any{
			"readOnlyHint":    false,
			"destructiveHint": true,
			"idempotentHint":  false,
			"openWorldHint":   false,
		},
	})
}

func toolFromDefinition(definition map[string]any) (Tool, error) {
	raw, err := json.Marshal(definition)
	if err != nil {
		return Tool{}, err
	}
	var def Tool
	if err := json.Unmarshal(raw, &def); err != nil {
		return Tool{}, err
	}
	return def, nil
}

// legacyToolNames rewrites the earlier tools' names, in the text of an answer
// the consolidated tools build on an earlier tool, into the consolidated tool
// that does the same. A client on the consolidated surface does not have the
// earlier tools in its list, so text that sends it to one sends it nowhere.
var legacyToolNames = strings.NewReplacer(
	StoreRequestModelsToolName, AccessToolName+` (action "request")`,
	StorePersonalKeyToolName, AccessToolName+` (action "key")`,
	StoreUninstallToolName, AccessToolName+` (action "uninstall")`,
	StoreInstallToolName, AccessToolName+` (action "install")`,
	StoreModelsToolName, SearchToolName+` (kind "model")`,
	StoreSearchToolName, SearchToolName+` (kind "catalog")`,
	ListAgentsToolName, SearchToolName+` (kind "agent")`,
	CallAgentToolName, GatewayCallToolName+` (with "agent")`,
	InventoryToolName, SearchToolName,
	CallToolName, GatewayCallToolName,
)

// withConsolidatedText rewrites the text blocks of a tool result for the
// consolidated surface (see legacyToolNames). Anything it cannot read is
// returned as it came: the answer is worth more than the wording.
func withConsolidatedText(result json.RawMessage) json.RawMessage {
	if len(result) == 0 {
		return result
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result, &fields); err != nil {
		return result
	}
	rawContent, ok := fields["content"]
	if !ok {
		return result
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(rawContent, &blocks); err != nil {
		return result
	}
	changed := false
	for _, block := range blocks {
		var kind string
		if err := json.Unmarshal(block["type"], &kind); err != nil || kind != "text" {
			continue
		}
		var text string
		if err := json.Unmarshal(block["text"], &text); err != nil {
			continue
		}
		rewritten := legacyToolNames.Replace(text)
		if rewritten == text {
			continue
		}
		encoded, err := json.Marshal(rewritten)
		if err != nil {
			continue
		}
		block["text"] = encoded
		changed = true
	}
	if !changed {
		return result
	}
	encoded, err := json.Marshal(blocks)
	if err != nil {
		return result
	}
	fields["content"] = encoded
	out, err := json.Marshal(fields)
	if err != nil {
		return result
	}
	return out
}

// structuredOf reads a tool result's isError and structuredContent. ok is
// false when the result cannot be read.
func structuredOf(result json.RawMessage) (isError bool, structured map[string]any, ok bool) {
	var envelope struct {
		IsError           bool           `json:"isError"`
		StructuredContent map[string]any `json:"structuredContent"`
	}
	if err := json.Unmarshal(result, &envelope); err != nil {
		return false, nil, false
	}
	return envelope.IsError, envelope.StructuredContent, true
}

// withStructuredFields adds fields to a tool result's structuredContent,
// creating it when the result has none.
func withStructuredFields(result json.RawMessage, add map[string]any) json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result, &fields); err != nil {
		return result
	}
	structured := map[string]any{}
	if raw, ok := fields["structuredContent"]; ok && len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &structured); err != nil {
			return result
		}
	}
	for key, value := range add {
		structured[key] = value
	}
	encoded, err := json.Marshal(structured)
	if err != nil {
		return result
	}
	fields["structuredContent"] = encoded
	out, err := json.Marshal(fields)
	if err != nil {
		return result
	}
	return out
}
