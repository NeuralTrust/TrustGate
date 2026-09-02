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

package plugins

// Product categories used to group policies in the catalog. The taxonomy lives
// here so it stays isolated from plugin execution code and can evolve without
// touching the plugin implementations.
const (
	groupTrafficControl   = "Traffic Control"
	groupQuota            = "Quota"
	groupRouting          = "Routing"
	groupPromptManagement = "Prompt Management"
	groupToolGovernance   = "Tool Governance"
	groupGuardrails       = "Guardrails"
	groupOther            = "Other"
)

// groupOrder fixes the order groups appear in the catalog response.
var groupOrder = []string{
	groupTrafficControl,
	groupQuota,
	groupRouting,
	groupPromptManagement,
	groupToolGovernance,
	groupGuardrails,
	groupOther,
}

// hiddenCatalogSlugs stay registered and executable but are excluded from the catalog.
var hiddenCatalogSlugs = map[string]struct{}{
	"model_allowlist": {},
	"tool_allowlist":  {},
}

// catalogMeta is the curated, UI-facing metadata for a plugin slug. Stage data
// is intentionally excluded; it is read from the plugin implementations so the
// catalog cannot drift from the executor's behaviour.
type catalogMeta struct {
	name        string
	group       string
	description string
	schema      SettingsSchema
}

// pluginCatalogMeta maps each built-in plugin slug to its catalog metadata and
// settings schema. Schemas are hand-authored from each plugin's config struct
// because those structs are private, use mapstructure tags, and carry semantic
// validation that reflection cannot express.
var pluginCatalogMeta = map[string]catalogMeta{
	"rate_limiter": {
		name:        "Rate Limiter",
		group:       groupTrafficControl,
		description: "Limit request volume with a sliding window. Counts gateway-wide for global policies, otherwise per consumer, with an optional header-based partition.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "limit",
					Label:       "Max Requests",
					Type:        FieldTypeInteger,
					Description: "Maximum number of requests allowed within the window.",
					Required:    true,
				},
				{
					Key:         "window",
					Label:       "Window",
					Type:        FieldTypeDuration,
					Description: "Sliding window duration, one second or longer (e.g. 1s, 1m, 1h).",
					Required:    true,
				},
				{
					Key:         "retry_after",
					Label:       "Retry After",
					Type:        FieldTypeString,
					Description: "Value sent in the Retry-After header, in seconds, when the limit is exceeded. Defaults to the window, which is when the budget actually returns.",
				},
				{
					Key:         "group_by_header",
					Label:       "Group By Header",
					Type:        FieldTypeString,
					Description: "Optional request header whose value sub-partitions the limit within the policy scope (e.g. X-User-Id). When empty, the limit is counted per gateway (global) or per consumer.",
				},
			},
		},
	},
	"request_size_limiter": {
		name:        "Request Size Limiter",
		group:       groupTrafficControl,
		description: "Reject requests whose body exceeds configured byte or character limits, and optionally require a Content-Length header before the request continues.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "allowed_payload_size",
					Label:       "Allowed Payload Size",
					Type:        FieldTypeInteger,
					Description: "Maximum payload size expressed in the selected size unit.",
					Required:    true,
					Default:     10,
				},
				{
					Key:         "size_unit",
					Label:       "Size Unit",
					Type:        FieldTypeEnum,
					Description: "Unit used to interpret the allowed payload size.",
					Enum:        enumOptions("bytes", "kilobytes", "megabytes"),
					Default:     "megabytes",
				},
				{
					Key:         "max_chars_per_request",
					Label:       "Max Characters Per Request",
					Type:        FieldTypeInteger,
					Description: "Maximum number of UTF-8 characters allowed in the request body. Leave it out to use the default; zero is not a valid ceiling.",
					Default:     100000,
				},
				{
					Key:         "require_content_length",
					Label:       "Require Content-Length",
					Type:        FieldTypeBoolean,
					Description: "Reject requests that do not declare a Content-Length header.",
					Default:     false,
				},
			},
		},
	},
	"token_rate_limiter": {
		name:        "LLM Budget",
		group:       groupQuota,
		description: "Cap LLM spend with token or dollar budgets over time windows, as one aggregate counter or per-model rules. Global applies gateway-wide; otherwise per consumer.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "unit",
					Label:       "Unit",
					Type:        FieldTypeEnum,
					Description: "Whether budgets count provider tokens or USD cost.",
					Enum:        enumOptions("tokens", "dollars"),
					Default:     "tokens",
				},
				{
					Key:         "counting",
					Label:       "Counting",
					Type:        FieldTypeEnum,
					Description: "Which usage figure accrues against the budget.",
					Enum:        enumOptions("total", "input", "output"),
					Default:     "total",
				},
				{
					Key:         "rules",
					Label:       "Per-Model Rules",
					Type:        FieldTypeArray,
					Description: "Per-model budgets. The most specific pattern wins, with an exact model preferred over a wildcard.",
					Item: &Field{
						Key:   "rule",
						Label: "Rule",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "model",
								Label:       "Model",
								Type:        FieldTypeString,
								Description: "Model slug or wildcard pattern (e.g. claude-opus-*).",
								Required:    true,
							},
							{
								Key:         "max",
								Label:       "Max",
								Type:        FieldTypeNumber,
								Description: "Budget ceiling in tokens or USD, matching the selected unit.",
								Required:    true,
							},
							{
								Key:         "time_window",
								Label:       "Time Window",
								Type:        FieldTypeString,
								Description: "Window duration such as 30m, 1h, or 1d. Values below 60s are raised to 60s.",
							},
						},
					},
				},
				{
					Key:         "aggregate",
					Label:       "Aggregate Budget",
					Type:        FieldTypeObject,
					Description: "Single budget counter for the whole scope, used when per-model rules are not set.",
					Fields: []Field{
						{
							Key:         "max",
							Label:       "Max",
							Type:        FieldTypeNumber,
							Description: "Budget ceiling in tokens or USD, matching the selected unit.",
							Required:    true,
						},
						{
							Key:         "time_window",
							Label:       "Time Window",
							Type:        FieldTypeString,
							Description: "Window duration such as 30m, 1h, or 1d. Values below 60s are raised to 60s.",
						},
					},
				},
				{
					Key:         "behavior_on_exceeded",
					Label:       "Behavior On Exceeded",
					Type:        FieldTypeEnum,
					Description: "Action taken when a budget is exceeded under enforce mode.",
					Enum:        enumOptions("reject", "downgrade_model"),
					Default:     "reject",
				},
				{
					Key:         "downgrade_to",
					Label:       "Downgrade To",
					Type:        FieldTypeString,
					Description: "Target model used when behavior is downgrade_model. Must be on the same provider.",
				},
				{
					Key:         "count_cache_reads",
					Label:       "Count Cache Reads",
					Type:        FieldTypeBoolean,
					Description: "Include Anthropic cache-read input tokens in counted and costed usage.",
					Default:     false,
				},
				{
					Key:         "custom_pricing",
					Label:       "Custom Pricing",
					Type:        FieldTypeMap,
					Description: "Per-token USD rates keyed by model slug or wildcard pattern, consulted before registry pricing and the models.dev catalog. Used for dollar budgets.",
					Value: &Field{
						Key:   "price",
						Label: "Price",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "input",
								Label:       "Input",
								Type:        FieldTypeNumber,
								Description: "Input price in USD per token.",
							},
							{
								Key:         "output",
								Label:       "Output",
								Type:        FieldTypeNumber,
								Description: "Output price in USD per token.",
							},
						},
					},
				},
				{
					Key:         "group_by_header",
					Label:       "Group By Header",
					Type:        FieldTypeString,
					Description: "Optional request header whose value sub-partitions the budget within the policy scope (e.g. X-User-Id). When empty, the budget is counted per gateway (global) or per consumer.",
				},
			},
		},
	},
	"per_tool_rate_limiter": {
		name:        "Per-Tool Rate Limiter",
		group:       groupTrafficControl,
		description: "Enforce limits per real tool execution across LLM and native MCP traffic, with sliding windows. Applies gateway-wide for global policies, otherwise per consumer.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "rules",
					Label:       "Rules",
					Type:        FieldTypeArray,
					Description: "Ordered list of per-tool rules. The first rule whose tool pattern matches a tool call wins.",
					Required:    true,
					Item: &Field{
						Key:   "rule",
						Label: "Rule",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "tool",
								Label:       "Tool",
								Type:        FieldTypeString,
								Description: "Glob pattern matched against the tool call name (e.g. execute_code*).",
								Required:    true,
							},
							{
								Key:         "windows",
								Label:       "Windows",
								Type:        FieldTypeArray,
								Description: "One or more fixed windows enforced for the matched tool.",
								Required:    true,
								Item: &Field{
									Key:   "window",
									Label: "Window",
									Type:  FieldTypeObject,
									Fields: []Field{
										{
											Key:         "duration",
											Label:       "Duration",
											Type:        FieldTypeDuration,
											Description: "Window duration (e.g. 1m, 1h).",
											Required:    true,
										},
										{
											Key:         "max",
											Label:       "Max Calls",
											Type:        FieldTypeInteger,
											Description: "Maximum number of tool calls allowed within the window.",
											Required:    true,
										},
									},
								},
							},
							{
								Key:         "behavior",
								Label:       "Behavior",
								Type:        FieldTypeEnum,
								Description: "Action when a window is exceeded. reject_response and strip_tool_from_request act on the next request (PreRequest); inject_error_result rewrites the response (PreResponse). Defaults to the policy-level default behavior. LLM consumers only: on MCP the gateway is the tool caller, so there is no request to rewrite and only reject_response can be attached.",
								Enum:        enumOptions("reject_response", "inject_error_result", "strip_tool_from_request"),
							},
						},
					},
				},
				{
					Key:         "behavior_default",
					Label:       "Default Behavior",
					Type:        FieldTypeEnum,
					Description: "Behavior applied to rules without an explicit behavior and to tools matched by a catch-all rule. LLM consumers only: on MCP a policy can only be attached with reject_response.",
					Enum:        enumOptions("reject_response", "inject_error_result", "strip_tool_from_request"),
					Default:     "reject_response",
				},
			},
		},
	},
	"semantic_cache": {
		name:        "Semantic Cache",
		group:       groupRouting,
		description: "Serve cached responses for exact or semantically similar requests. Configure match mode, cache scope, and the vector store used for similarity lookup.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "mode",
					Label:       "Mode",
					Type:        FieldTypeEnum,
					Description: "Match strategy: exact (normalized text equality), semantic (embedding similarity), or both.",
					Enum:        enumOptions("exact", "semantic", "both"),
					Default:     "semantic",
				},
				{
					Key:         "scope",
					Label:       "Scope",
					Type:        FieldTypeEnum,
					Description: "Cache partition scope: consumer isolates entries per consumer, global shares them gateway-wide.",
					Enum:        enumOptions("consumer", "global"),
					Default:     "consumer",
				},
				{
					Key:         "vector_store",
					Label:       "Vector Store",
					Type:        FieldTypeEnum,
					Description: "Backing store for cached embeddings and responses.",
					Enum:        enumOptions("redis", "pgvector", "in_memory"),
					Default:     "redis",
				},
				{
					Key:         "similarity_threshold",
					Label:       "Similarity Threshold",
					Type:        FieldTypeNumber,
					Description: "Cosine similarity threshold in (0, 1] required to serve a cache hit.",
					Default:     0.85,
				},
				{
					Key:         "ttl_seconds",
					Label:       "TTL (seconds)",
					Type:        FieldTypeInteger,
					Description: "How long cached responses remain valid, in seconds. Takes precedence over the legacy ttl duration.",
				},
				{
					Key:         "embedding_provider",
					Label:       "Embedding Provider",
					Type:        FieldTypeString,
					Description: "Embedding provider used to vectorize requests.",
				},
				{
					Key:         "embedding_model",
					Label:       "Embedding Model",
					Type:        FieldTypeString,
					Description: "Embedding model name.",
				},
				{
					Key:         "cache_only_on_status",
					Label:       "Cache Only On Status",
					Type:        FieldTypeArray,
					Description: "HTTP status codes whose responses may be cached. Empty allows any 2xx.",
					Default:     []int{200},
					Item:        &Field{Key: "status", Label: "Status", Type: FieldTypeInteger},
				},
				{
					Key:         "bypass_header",
					Label:       "Bypass Header",
					Type:        FieldTypeString,
					Description: "Request header whose presence bypasses cache lookup and store.",
					Default:     "X-Cache-Bypass",
				},
				{
					Key:         "skip_if_tools_present",
					Label:       "Skip If Tools Present",
					Type:        FieldTypeBoolean,
					Description: "Skip caching when the request carries tool definitions or the response contains tool calls.",
					Default:     true,
				},
				{
					Key:         "skip_if_streaming",
					Label:       "Skip If Streaming",
					Type:        FieldTypeBoolean,
					Description: "Skip caching for streaming requests and responses.",
					Default:     false,
				},
				{
					Key:         "ttl",
					Label:       "TTL",
					Type:        FieldTypeDuration,
					Description: "Legacy duration for how long cached responses remain valid (e.g. 24h). Superseded by ttl_seconds.",
					Default:     "24h",
				},
				{
					Key:   "embedding",
					Label: "Embedding",
					Type:  FieldTypeObject,
					Fields: []Field{
						{
							Key:         "provider",
							Label:       "Provider",
							Type:        FieldTypeString,
							Description: "Embedding provider used to vectorize requests.",
							Default:     "openai",
						},
						{
							Key:         "model",
							Label:       "Model",
							Type:        FieldTypeString,
							Description: "Embedding model name.",
							Default:     "text-embedding-ada-002",
						},
						{
							Key:         "api_key",
							Label:       "API Key",
							Type:        FieldTypeString,
							Description: "Credential for the embedding provider.",
						},
					},
				},
			},
		},
	},
	"model_allowlist": {
		name:        "Model Allowlist",
		group:       groupRouting,
		description: "Restrict which models a consumer or gateway may call, matching names with glob patterns. Reject disallowed models with a 403 or transparently substitute them.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "allowed_models",
					Label:       "Allowed Models",
					Type:        FieldTypeArray,
					Description: "Model name patterns permitted. Use * as a wildcard (e.g. gpt-5*).",
					Required:    true,
					Item:        &Field{Key: "model", Label: "Model", Type: FieldTypeString},
				},
				{
					Key:         "behavior_on_disallowed",
					Label:       "Behavior On Disallowed",
					Type:        FieldTypeEnum,
					Description: "Action taken when a requested model is not in the allowlist.",
					Enum:        enumOptions("reject", "substitute"),
					Default:     "reject",
				},
				{
					Key:         "substitute_with",
					Label:       "Substitute With",
					Type:        FieldTypeString,
					Description: "Model written back when behavior is substitute. Must match the allowlist.",
				},
				{
					Key:         "default_model",
					Label:       "Default Model",
					Type:        FieldTypeString,
					Description: "Model injected when the request omits one. Must match the allowlist.",
				},
			},
		},
	},
	"tool_allowlist": {
		name:        "Tool Allowlist",
		group:       groupRouting,
		description: "Control which tools appear on the request with allow and deny glob patterns. Deny wins; choose how to handle an empty tools list after filtering.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "allow_tools",
					Label:       "Allow Tools",
					Type:        FieldTypeArray,
					Description: "Glob patterns; if set, only matching tools pass.",
					Item:        &Field{Key: "pattern", Label: "Pattern", Type: FieldTypeString},
				},
				{
					Key:         "deny_tools",
					Label:       "Deny Tools",
					Type:        FieldTypeArray,
					Description: "Glob patterns removed after allow_tools (deny overrides allow).",
					Item:        &Field{Key: "pattern", Label: "Pattern", Type: FieldTypeString},
				},
				{
					Key:         "on_empty_after_filter",
					Label:       "On Empty After Filter",
					Type:        FieldTypeEnum,
					Description: "Behavior when filtering removes every tool from the request.",
					Enum:        enumOptions("reject", "pass_through_empty", "strip_tools_field"),
					Default:     "reject",
				},
				{
					Key:         "scope",
					Label:       "Scope",
					Type:        FieldTypeEnum,
					Description: "Informational; effective scope derives from the policy global flag.",
					Enum:        enumOptions("consumer", "global"),
				},
			},
		},
	},
	"prompt_template": {
		name:        "Prompt Template",
		group:       groupPromptManagement,
		description: "Inject context-bound system prompts (Mode A) and/or render client-referenced named, versioned templates (Mode B) into the request before it reaches the model.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "template_engine",
					Label:       "Template Engine",
					Type:        FieldTypeEnum,
					Description: "Placeholder rendering engine. Only mustache is supported in v1.",
					Enum:        enumOptions("mustache"),
					Default:     "mustache",
				},
				{
					Key:         "context_variables",
					Label:       "Context Variables",
					Type:        FieldTypeMap,
					Description: "Named gateway-side variables resolved from the inbound request and substituted into templates.",
					Value: &Field{
						Key:   "var",
						Label: "Variable",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "source",
								Label:       "Source",
								Type:        FieldTypeEnum,
								Description: "Where the variable value is read from.",
								Enum:        enumOptions("header", "jwt_claim"),
								Required:    true,
							},
							{
								Key:         "name",
								Label:       "Name",
								Type:        FieldTypeString,
								Description: "Header name or JWT claim name to read.",
								Required:    true,
							},
						},
					},
				},
				{
					Key:         "inject_templates",
					Label:       "Inject Templates",
					Type:        FieldTypeArray,
					Description: "Mode A: system prompts rendered from context variables and injected into the request.",
					Item: &Field{
						Key:   "tmpl",
						Label: "Template",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "id",
								Label:       "ID",
								Type:        FieldTypeString,
								Description: "Unique identifier for the injected template.",
								Required:    true,
							},
							{
								Key:         "position",
								Label:       "Position",
								Type:        FieldTypeEnum,
								Description: "Where the rendered content is injected. Only system is supported in v1.",
								Enum:        enumOptions("system"),
								Default:     "system",
							},
							{
								Key:         "role",
								Label:       "Role",
								Type:        FieldTypeString,
								Description: "Message role used when inserting the rendered content.",
								Default:     "system",
							},
							{
								Key:         "content",
								Label:       "Content",
								Type:        FieldTypeString,
								Description: "Template body with {{variable}} placeholders.",
								Required:    true,
							},
							{
								Key:         "on_existing_system",
								Label:       "On Existing System",
								Type:        FieldTypeEnum,
								Description: "How to combine with an existing system prompt.",
								Enum:        enumOptions("merge", "replace"),
								Default:     "merge",
							},
						},
					},
				},
				{
					Key:         "named_templates",
					Label:       "Named Templates",
					Type:        FieldTypeArray,
					Description: "Mode B: named, versioned templates referenced by clients via {template://name@label}.",
					Item: &Field{
						Key:   "nt",
						Label: "Named Template",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "name",
								Label:       "Name",
								Type:        FieldTypeString,
								Description: "Template name referenced by clients.",
								Required:    true,
							},
							{
								Key:         "versions",
								Label:       "Versions",
								Type:        FieldTypeArray,
								Description: "Versions of this template, each addressable by labels.",
								Item: &Field{
									Key:   "v",
									Label: "Version",
									Type:  FieldTypeObject,
									Fields: []Field{
										{
											Key:         "labels",
											Label:       "Labels",
											Type:        FieldTypeArray,
											Description: "Labels that resolve to this version (e.g. stable). At least one is required to address the version.",
											Item:        &Field{Key: "label", Label: "Label", Type: FieldTypeString},
											Required:    true,
										},
										{
											Key:         "content",
											Label:       "Content",
											Type:        FieldTypeString,
											Description: "Template body rendered into the request messages fragment.",
											Required:    true,
										},
										{
											Key:         "required_variables",
											Label:       "Required Variables",
											Type:        FieldTypeMap,
											Description: "Client variables validated against this version before rendering.",
											Value: &Field{
												Key:   "rv",
												Label: "Required Variable",
												Type:  FieldTypeObject,
												Fields: []Field{
													{
														Key:         "type",
														Label:       "Type",
														Type:        FieldTypeEnum,
														Description: "Expected scalar type of the client value.",
														Enum:        enumOptions("string", "number", "boolean"),
													},
													{
														Key:         "enum",
														Label:       "Enum",
														Type:        FieldTypeArray,
														Description: "Allowed values for the client variable.",
														Item:        &Field{Key: "opt", Label: "Option", Type: FieldTypeString},
													},
													{
														Key:         "max_length",
														Label:       "Max Length",
														Type:        FieldTypeInteger,
														Description: "Maximum string length allowed for the client value.",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				{
					Key:         "allow_untemplated_requests",
					Label:       "Allow Untemplated Requests",
					Type:        FieldTypeBoolean,
					Description: "When false and named templates are configured, reject requests without a template reference.",
					Default:     true,
				},
				{
					Key:         "on_missing_context_variable",
					Label:       "On Missing Context Variable",
					Type:        FieldTypeEnum,
					Description: "Behavior when a context variable cannot be resolved.",
					Enum:        enumOptions("error", "empty_string", "skip_injection"),
					Default:     "error",
				},
				{
					Key:         "on_missing_client_variable",
					Label:       "On Missing Client Variable",
					Type:        FieldTypeEnum,
					Description: "Behavior when a non-required client variable is absent.",
					Enum:        enumOptions("error", "empty_string"),
					Default:     "error",
				},
				{
					Key:         "default_label",
					Label:       "Default Label",
					Type:        FieldTypeString,
					Description: "Label used when a template reference omits @label.",
				},
				{
					Key:         "escape_json_control_chars",
					Label:       "Escape JSON Control Chars",
					Type:        FieldTypeBoolean,
					Description: "Strip raw C0 control bytes from substituted values before insertion.",
					Default:     true,
				},
			},
		},
	},
	"prompt_compression": {
		name:        "Prompt Compression",
		group:       groupPromptManagement,
		description: "Shrink the request prompt before the model: minify JSON, strip ANSI escapes, and collapse whitespace. Deterministic and fail-open to keep prompt caches stable.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "compress_json",
					Label:       "Compress JSON",
					Type:        FieldTypeBoolean,
					Description: "Minify standalone JSON message content, ```json fenced blocks and tool-call arguments. At least one transform must stay enabled.",
					Default:     true,
				},
				{
					Key:         "normalize_whitespace",
					Label:       "Normalize Whitespace",
					Type:        FieldTypeBoolean,
					Description: "Trim trailing spaces per line, keeping Markdown hard line breaks, and collapse runs of blank lines.",
					Default:     true,
				},
				{
					Key:         "strip_ansi",
					Label:       "Strip ANSI Escapes",
					Type:        FieldTypeBoolean,
					Description: "Remove ANSI colour and cursor sequences, common in captured terminal and CI logs.",
					Default:     true,
				},
				{
					Key:         "max_consecutive_blank_lines",
					Label:       "Max Consecutive Blank Lines",
					Type:        FieldTypeInteger,
					Description: "Longest run of blank lines kept when whitespace is normalized. Between 1 and 1000.",
					Default:     1,
				},
				{
					Key:         "min_length",
					Label:       "Minimum Content Length",
					Type:        FieldTypeInteger,
					Description: "Skip message content shorter than this many bytes; 0 compresses everything. Leaving small messages byte-identical protects provider prompt-cache prefixes.",
					Default:     256,
				},
				{
					Key:         "max_body_bytes",
					Label:       "Max Body Bytes",
					Type:        FieldTypeInteger,
					Description: "Skip the whole pipeline for request bodies larger than this, bounding per-request CPU cost; 0 disables the cap.",
					Default:     1048576,
				},
				{
					Key:         "target_roles",
					Label:       "Target Roles",
					Type:        FieldTypeArray,
					Description: "Restrict compression to messages with these roles. Empty compresses every role.",
					Item: &Field{
						Key:   "role",
						Label: "Role",
						Type:  FieldTypeEnum,
						Enum:  enumOptions("system", "user", "assistant", "tool"),
					},
				},
			},
		},
	},
	"tool_injection": {
		name:        "Tool Injection",
		group:       groupToolGovernance,
		description: "Inject operator-authored tools into the request before the model runs. Name collisions follow the on_conflict policy; this is governance, not an access gate.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "inject_tools",
					Label:       "Inject Tools",
					Type:        FieldTypeArray,
					Description: "Operator-authored tools appended to the request. Name collisions are resolved by the on_conflict policy.",
					Required:    true,
					Item: &Field{
						Key:   "inject",
						Label: "Inject",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "type",
								Label:       "Type",
								Type:        FieldTypeEnum,
								Description: "Tool kind. Only function tools are supported.",
								Enum:        enumOptions("function"),
								Default:     "function",
							},
							{
								Key:         "function",
								Label:       "Function",
								Type:        FieldTypeObject,
								Description: "Function tool definition to inject.",
								Fields: []Field{
									{
										Key:         "name",
										Label:       "Name",
										Type:        FieldTypeString,
										Description: "Injected tool name.",
										Required:    true,
									},
									{
										Key:         "description",
										Label:       "Description",
										Type:        FieldTypeString,
										Description: "Injected tool description.",
									},
									{
										Key:         "parameters",
										Label:       "Parameters",
										Type:        FieldTypeObject,
										Description: "Injected tool parameter schema. Free-form JSON; edited as a raw object.",
									},
								},
							},
						},
					},
				},
				{
					Key:         "on_conflict",
					Label:       "On Conflict",
					Type:        FieldTypeEnum,
					Description: "Resolution when an injected tool name collides with a surviving or already-injected tool.",
					Enum:        enumOptions("gateway_wins", "client_wins", "reject"),
					Default:     "gateway_wins",
				},
				{
					Key:         "scope",
					Label:       "Scope",
					Type:        FieldTypeEnum,
					Description: "Informational; effective scope derives from the policy global flag.",
					Enum:        enumOptions("consumer", "global"),
				},
			},
		},
	},
	"trustguard": {
		name:        "TrustGuard",
		group:       groupGuardrails,
		description: "Inspect request or response content with TrustGuard, block flagged material, and apply data-masking. Fails open on guard errors. Streaming responses are inspected after the stream completes (post_response), not live.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "direction",
					Label:       "Direction",
					Type:        FieldTypeEnum,
					Description: "Which legs to inspect: the request, the response, or both.",
					Enum:        enumOptions("request", "response", "request_response"),
					// Matches the plugin's own defaultDirection. The two used to
					// disagree — the catalog prefilled "request" — so a guardrail
					// policy created through the console inspected the request leg
					// only, leaving every response-side detector off with nothing
					// saying so.
					Default: "request_response",
				},
				{
					Key:         "collector_id",
					Label:       "Collector ID",
					Type:        FieldTypeString,
					Description: "TrustGuard collector UUID bound to this gateway policy.",
					Required:    true,
				},
			},
		},
	},
	"openai_moderation": {
		name:        "OpenAI Moderation",
		group:       groupGuardrails,
		description: "Screen request or response text with the OpenAI Moderations API and block content that crosses category thresholds. Fails closed in enforce mode. Text-only.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "api_key",
					Label:       "API Key",
					Type:        FieldTypeString,
					Description: "OpenAI credential sent as a Bearer token to the Moderations API.",
					Required:    true,
				},
				{
					Key:         "model",
					Label:       "Model",
					Type:        FieldTypeString,
					Description: "Moderations model.",
					Default:     "omni-moderation-latest",
				},
				{
					Key:         "stages",
					Label:       "Stages",
					Type:        FieldTypeArray,
					Description: "Legs to inspect.",
					Item: &Field{
						Key:   "stage",
						Label: "Stage",
						Type:  FieldTypeEnum,
						Enum:  enumOptions("pre_request", "pre_response"),
					},
				},
				{
					Key:         "categories",
					Label:       "Categories",
					Type:        FieldTypeArray,
					Description: "Allow-list of categories to evaluate. Empty evaluates all categories returned by OpenAI.",
					Item: &Field{
						Key:   "category",
						Label: "Category",
						Type:  FieldTypeString,
					},
				},
				{
					Key:         "thresholds",
					Label:       "Thresholds",
					Type:        FieldTypeMap,
					Description: "Per-category score threshold (0..1). A score at or above the threshold blocks.",
					Value: &Field{
						Key:   "threshold",
						Label: "Threshold",
						Type:  FieldTypeNumber,
					},
				},
				{
					Key:         "block_on_flagged",
					Label:       "Block On Flagged",
					Type:        FieldTypeBoolean,
					Description: "Block any category OpenAI marks flagged, even without a configured threshold.",
					Default:     false,
				},
				{
					Key:   "action",
					Label: "Action",
					Type:  FieldTypeObject,
					Fields: []Field{
						{
							Key:         "message",
							Label:       "Message",
							Type:        FieldTypeString,
							Description: "Block message returned to the caller.",
						},
					},
				},
			},
		},
	},
	"azure_content_safety": {
		name:        "Azure Content Safety",
		group:       groupGuardrails,
		description: "Screen request text with Azure AI Content Safety and block categories whose severity meets the configured threshold. Fails closed in enforce mode.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "api_key",
					Label:       "API Key",
					Type:        FieldTypeString,
					Description: "Azure Content Safety subscription key sent as the Ocp-Apim-Subscription-Key header.",
					Required:    true,
				},
				{
					Key:         "endpoint",
					Label:       "Endpoint",
					Type:        FieldTypeString,
					Description: "Absolute Analyze Text endpoint URL for the Azure Content Safety resource.",
					Required:    true,
				},
				{
					Key:         "output_type",
					Label:       "Output Type",
					Type:        FieldTypeEnum,
					Description: "Severity scale returned by Azure: four levels (0/2/4/6) or eight levels (0-7).",
					Enum:        enumOptions("FourSeverityLevels", "EightSeverityLevels"),
					Default:     "FourSeverityLevels",
				},
				{
					Key:         "categories",
					Label:       "Categories",
					Type:        FieldTypeArray,
					Description: "Harm categories sent to Azure for analysis. Defaults to all four when empty.",
					Item: &Field{
						Key:   "category",
						Label: "Category",
						Type:  FieldTypeEnum,
						Enum:  enumOptions("Hate", "Violence", "SelfHarm", "Sexual"),
					},
				},
				{
					Key:         "category_severity",
					Label:       "Category Severity",
					Type:        FieldTypeMap,
					Description: "Per-category severity thresholds. A category breaches when its returned severity meets or exceeds its threshold. Only categories listed here are enforced.",
					Required:    true,
					KeyOptions:  []string{"Hate", "Violence", "SelfHarm", "Sexual"},
					Value:       &Field{Key: "severity", Label: "Severity", Type: FieldTypeInteger},
				},
				{
					Key:         "message",
					Label:       "Block Message",
					Type:        FieldTypeString,
					Description: "Optional message returned to the caller when content is blocked.",
				},
			},
		},
	},
	"bedrock_guardrail": {
		name:        "AWS Bedrock Guardrail",
		group:       groupGuardrails,
		description: "Apply an AWS Bedrock guardrail to prompts and/or responses, blocking flagged content or anonymizing PII in place. Streaming responses pass through untouched.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "guardrail_id",
					Label:       "Guardrail ID",
					Type:        FieldTypeString,
					Description: "AWS Bedrock guardrail identifier.",
					Required:    true,
				},
				{
					Key:         "version",
					Label:       "Version",
					Type:        FieldTypeString,
					Description: "Guardrail version. Defaults to DRAFT.",
					Default:     "DRAFT",
				},
				{
					Key:         "pii_action",
					Label:       "PII Action",
					Type:        FieldTypeEnum,
					Description: "How TrustGate reacts when the sensitive-information policy fires: block the call or anonymize the matched spans in place.",
					Enum:        enumOptions("block", "anonymize"),
					Default:     "block",
				},
				{
					Key:         "message",
					Label:       "Block Message",
					Type:        FieldTypeString,
					Description: "Optional operator message; the 403 body always carries the matched policy and name.",
				},
				{
					Key:      "credentials",
					Label:    "AWS Credentials",
					Type:     FieldTypeObject,
					Required: true,
					Fields: []Field{
						{
							Key:         "aws_region",
							Label:       "AWS Region",
							Type:        FieldTypeString,
							Description: "AWS region hosting the guardrail.",
							Default:     "us-east-1",
						},
						{
							Key:         "use_role",
							Label:       "Use IAM Role",
							Type:        FieldTypeBoolean,
							Description: "Assume an IAM role via STS. On EKS, omit access keys and use the pod IRSA identity as the base.",
							Default:     false,
						},
						{
							Key:         "role_arn",
							Label:       "Role ARN",
							Type:        FieldTypeString,
							Description: "Required when Use IAM Role is enabled.",
						},
						{
							Key:         "session_name",
							Label:       "Session Name",
							Type:        FieldTypeString,
							Description: "STS assume-role session name.",
							Default:     "BedrockClientSession",
						},
						{
							Key:         "access_key_id",
							Label:       "Access Key ID",
							Type:        FieldTypeString,
							Description: "Optional when Use IAM Role is enabled (IRSA / default chain). Required for static-key auth.",
						},
						{
							Key:         "secret_access_key",
							Label:       "Secret Access Key",
							Type:        FieldTypeString,
							Description: "Optional when Use IAM Role is enabled (IRSA / default chain). Required for static-key auth.",
						},
						{
							Key:         "session_token",
							Label:       "Session Token",
							Type:        FieldTypeString,
							Description: "Optional temporary-credential session token.",
						},
					},
				},
			},
		},
	},
	"regex_replace": {
		name:        "Regex Replace",
		group:       groupGuardrails,
		description: "Rewrite the request prompt or LLM response with ordered RE2 regex rules that chain, each seeing the previous output. Streaming responses pass through untouched.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "target",
					Label:       "Target",
					Type:        FieldTypeEnum,
					Description: "Which leg to rewrite. A single instance rewrites the request prompt or the LLM response, not both.",
					Required:    true,
					Enum:        enumOptions("request", "response"),
				},
				{
					Key:         "rules",
					Label:       "Rules",
					Type:        FieldTypeArray,
					Description: "Ordered replacement rules. Each rule's output feeds the next.",
					Required:    true,
					Item: &Field{
						Key:   "rule",
						Label: "Rule",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "pattern",
								Label:       "Pattern",
								Type:        FieldTypeString,
								Description: "RE2 regular expression. Backreferences and lookaround are not supported.",
								Required:    true,
							},
							{
								Key:         "replacement",
								Label:       "Replacement",
								Type:        FieldTypeString,
								Description: "Replacement text. Use $1 or ${name} to reference capture groups. Empty removes the match.",
							},
							{
								Key:         "case_insensitive",
								Label:       "Case Insensitive",
								Type:        FieldTypeBoolean,
								Description: "Match without regard to letter case ((?i)).",
								Default:     false,
							},
							{
								Key:         "multiline",
								Label:       "Multiline",
								Type:        FieldTypeBoolean,
								Description: "^ and $ match at line boundaries ((?m)).",
								Default:     false,
							},
						},
					},
				},
			},
		},
	},
}
