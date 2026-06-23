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
	groupTrafficControl = "Traffic Control"
	groupQuota          = "Quota"
	groupRouting        = "Routing"
	groupOther          = "Other"
)

// groupOrder fixes the order groups appear in the catalog response.
var groupOrder = []string{
	groupTrafficControl,
	groupQuota,
	groupRouting,
	groupOther,
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
		description: "Limit request volume using a sliding window. The limit applies gateway-wide when the policy is global, otherwise per consumer.",
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
					Description: "Sliding window duration (e.g. 1s, 1m, 1h).",
					Required:    true,
				},
				{
					Key:         "retry_after",
					Label:       "Retry After",
					Type:        FieldTypeString,
					Description: "Value sent in the Retry-After header, in seconds, when the limit is exceeded.",
					Default:     "60",
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
		description: "Reject requests whose body exceeds configured byte or character limits.",
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
					Enum:        []string{"bytes", "kilobytes", "megabytes"},
					Default:     "megabytes",
				},
				{
					Key:         "max_chars_per_request",
					Label:       "Max Characters Per Request",
					Type:        FieldTypeInteger,
					Description: "Maximum number of UTF-8 characters allowed in the request body.",
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
	"cors": {
		name:        "CORS",
		group:       groupTrafficControl,
		description: "Validate request origins and apply Cross-Origin Resource Sharing response headers.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "allowed_origins",
					Label:       "Allowed Origins",
					Type:        FieldTypeArray,
					Description: "Origins permitted to access the resource. Use * to allow any origin.",
					Required:    true,
					Item:        &Field{Key: "origin", Label: "Origin", Type: FieldTypeString},
				},
				{
					Key:         "allowed_methods",
					Label:       "Allowed Methods",
					Type:        FieldTypeArray,
					Description: "HTTP methods permitted in cross-origin requests.",
					Item: &Field{
						Key:   "method",
						Label: "Method",
						Type:  FieldTypeEnum,
						Enum:  []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"},
					},
				},
				{
					Key:         "allow_credentials",
					Label:       "Allow Credentials",
					Type:        FieldTypeBoolean,
					Description: "Allow cookies and credentials in cross-origin requests.",
					Default:     false,
				},
				{
					Key:         "expose_headers",
					Label:       "Expose Headers",
					Type:        FieldTypeArray,
					Description: "Response headers exposed to the browser.",
					Item:        &Field{Key: "header", Label: "Header", Type: FieldTypeString},
				},
				{
					Key:         "max_age",
					Label:       "Max Age",
					Type:        FieldTypeDuration,
					Description: "How long the preflight response may be cached (e.g. 1h).",
				},
				{
					Key:         "log_violations",
					Label:       "Log Violations",
					Type:        FieldTypeBoolean,
					Description: "Log requests from disallowed origins.",
					Default:     false,
				},
			},
		},
	},
	"token_rate_limiter": {
		name:        "Token & Dollar Budget + Cost Cap",
		group:       groupQuota,
		description: "Enforce LLM token or dollar budgets (aggregate or per-model) over fixed windows, plus a stateless per-request cost cap on model list price. Budgets and the cost cap apply gateway-wide when the policy is global, otherwise per consumer. All fields are optional; a legacy window-only config keeps its original aggregate token-budget behaviour.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "unit",
					Label:       "Unit",
					Type:        FieldTypeEnum,
					Description: "Whether budgets count provider tokens or USD cost.",
					Enum:        []string{"tokens", "dollars"},
					Default:     "tokens",
				},
				{
					Key:         "per_model",
					Label:       "Per Model",
					Type:        FieldTypeBoolean,
					Description: "Account budgets per model using rules instead of a single aggregate counter.",
					Default:     false,
				},
				{
					Key:         "counting",
					Label:       "Counting",
					Type:        FieldTypeEnum,
					Description: "Which usage figure accrues against the budget.",
					Enum:        []string{"total", "input", "output"},
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
					Enum:        []string{"reject", "throttle", "downgrade_model", "alert_only"},
					Default:     "reject",
				},
				{
					Key:         "downgrade_to",
					Label:       "Downgrade To",
					Type:        FieldTypeString,
					Description: "Target model used when behavior is downgrade_model. Must be on the same provider.",
				},
				{
					Key:         "stream_usage_injection",
					Label:       "Stream Usage Injection",
					Type:        FieldTypeBoolean,
					Description: "Request and inject usage on streaming responses so accrual works on streams.",
					Default:     false,
				},
				{
					Key:         "count_cache_reads",
					Label:       "Count Cache Reads",
					Type:        FieldTypeBoolean,
					Description: "Include Anthropic cache-read input tokens in counted and costed usage.",
					Default:     false,
				},
				{
					Key:         "cost_cap",
					Label:       "Cost Cap",
					Type:        FieldTypeObject,
					Description: "Stateless per-request guard that rejects or downgrades models whose list price per 1k tokens exceeds the configured ceiling.",
					Fields: []Field{
						{
							Key:         "enabled",
							Label:       "Enabled",
							Type:        FieldTypeBoolean,
							Description: "Turn the cost cap on.",
							Default:     false,
						},
						{
							Key:         "max_input_cost_per_1k_tokens",
							Label:       "Max Input Cost Per 1k Tokens",
							Type:        FieldTypeNumber,
							Description: "Global input-price ceiling in USD per 1k tokens.",
						},
						{
							Key:         "max_output_cost_per_1k_tokens",
							Label:       "Max Output Cost Per 1k Tokens",
							Type:        FieldTypeNumber,
							Description: "Global output-price ceiling in USD per 1k tokens.",
						},
						{
							Key:         "per_model_overrides",
							Label:       "Per-Model Overrides",
							Type:        FieldTypeMap,
							Description: "Per-model ceilings keyed by model slug or wildcard pattern.",
							Value: &Field{
								Key:   "ceiling",
								Label: "Ceiling",
								Type:  FieldTypeObject,
								Fields: []Field{
									{
										Key:         "max_input_cost_per_1k_tokens",
										Label:       "Max Input Cost Per 1k Tokens",
										Type:        FieldTypeNumber,
										Description: "Input-price ceiling in USD per 1k tokens.",
									},
									{
										Key:         "max_output_cost_per_1k_tokens",
										Label:       "Max Output Cost Per 1k Tokens",
										Type:        FieldTypeNumber,
										Description: "Output-price ceiling in USD per 1k tokens.",
									},
								},
							},
						},
						{
							Key:         "behavior_on_violation",
							Label:       "Behavior On Violation",
							Type:        FieldTypeEnum,
							Description: "Action taken when a model exceeds its cost ceiling.",
							Enum:        []string{"reject", "downgrade"},
							Default:     "reject",
						},
						{
							Key:         "downgrade_to",
							Label:       "Downgrade To",
							Type:        FieldTypeString,
							Description: "Target model used when behavior is downgrade. Must be on the same provider.",
						},
						{
							Key:         "unknown_model",
							Label:       "Unknown Model",
							Type:        FieldTypeEnum,
							Description: "How to treat a model with no resolvable price.",
							Enum:        []string{"reject", "pass_through", "assume_max"},
							Default:     "reject",
						},
					},
				},
				{
					Key:         "pricing_table",
					Label:       "Pricing Table",
					Type:        FieldTypeEnum,
					Description: "Price source: builtin catalog or a custom overlay.",
					Enum:        []string{"builtin", "custom"},
					Default:     "builtin",
				},
				{
					Key:         "custom_pricing",
					Label:       "Custom Pricing",
					Type:        FieldTypeMap,
					Description: "Per-token USD rates keyed by model slug or wildcard pattern, consulted before the builtin table.",
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
					Key:         "window",
					Label:       "Window",
					Type:        FieldTypeObject,
					Description: "Legacy single-window aggregate token budget, kept for backward compatibility.",
					Fields: []Field{
						{
							Key:         "unit",
							Label:       "Unit",
							Type:        FieldTypeEnum,
							Description: "Time unit of the budget window.",
							Enum:        []string{"second", "minute", "hour", "day"},
						},
						{
							Key:         "max",
							Label:       "Max Tokens",
							Type:        FieldTypeInteger,
							Description: "Maximum number of tokens allowed within the window.",
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
		description: "Count and enforce limits per observed tool call in model responses. The limit applies gateway-wide when the policy is global, otherwise per consumer.",
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
								Description: "Action when a window is exceeded. reject_response and strip_tool_from_request act on the next request (PreRequest); inject_error_result rewrites the response (PreResponse). Defaults to the policy-level default behavior.",
								Enum:        []string{"reject_response", "inject_error_result", "strip_tool_from_request"},
							},
						},
					},
				},
				{
					Key:         "behavior_default",
					Label:       "Default Behavior",
					Type:        FieldTypeEnum,
					Description: "Behavior applied to rules without an explicit behavior and to tools matched by a catch-all rule.",
					Enum:        []string{"reject_response", "inject_error_result", "strip_tool_from_request"},
					Default:     "reject_response",
				},
				{
					Key:         "scope",
					Label:       "Scope",
					Type:        FieldTypeEnum,
					Description: "Informational; effective scope derives from the policy global flag.",
					Enum:        []string{"consumer", "global"},
				},
			},
		},
	},
	"semantic_cache": {
		name:        "Semantic Cache",
		group:       groupRouting,
		description: "Serve cached responses for semantically similar requests, scoped per registry.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "similarity_threshold",
					Label:       "Similarity Threshold",
					Type:        FieldTypeNumber,
					Description: "Cosine similarity threshold in (0, 1] required to serve a cache hit.",
					Default:     0.85,
				},
				{
					Key:         "ttl",
					Label:       "TTL",
					Type:        FieldTypeDuration,
					Description: "How long cached responses remain valid (e.g. 24h).",
					Default:     "24h",
				},
				{
					Key:      "embedding",
					Label:    "Embedding",
					Type:     FieldTypeObject,
					Required: true,
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
							Required:    true,
						},
					},
				},
			},
		},
	},
	"model_allowlist": {
		name:        "Model Allowlist",
		group:       groupRouting,
		description: "Restrict which models a consumer or gateway may call, matching by name with glob patterns. Reject disallowed models with a 403 or transparently substitute them.",
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
					Enum:        []string{"reject", "substitute"},
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
		description: "Glob-based access control for the request tools[] array: allow_tools whitelists patterns and deny_tools removes patterns (deny overrides allow) before the model sees the tools. When filtering empties the array, reject the request, strip the tools field, or pass through an empty array. Scope is informational; effective scope derives from the policy global flag.",
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
					Enum:        []string{"reject", "pass_through_empty", "strip_tools_field"},
					Default:     "reject",
				},
				{
					Key:         "scope",
					Label:       "Scope",
					Type:        FieldTypeEnum,
					Description: "Informational; effective scope derives from the policy global flag.",
					Enum:        []string{"consumer", "global"},
				},
			},
		},
	},
	"tool_call_validation": {
		name:        "Tool Call Validation",
		group:       groupOther,
		description: "Validate the tool calls an LLM returns against per-tool rules, rejecting or redacting responses that violate them.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "scope",
					Label:       "Scope",
					Type:        FieldTypeString,
					Description: "Reserved for future use; currently inert and ignored by the plugin.",
				},
				{
					Key:         "semantic",
					Label:       "Semantic",
					Type:        FieldTypeObject,
					Description: "LLM provider settings used by semantic validators. Required when any rule uses the semantic validator.",
					Fields: []Field{
						{
							Key:         "provider",
							Label:       "Provider",
							Type:        FieldTypeEnum,
							Description: "LLM provider backing semantic validation.",
							Enum:        []string{"openai"},
							Default:     "openai",
						},
						{
							Key:         "api_key",
							Label:       "API Key",
							Type:        FieldTypeString,
							Description: "Credential for the semantic provider. Required when the semantic block is used.",
						},
						{
							Key:         "model",
							Label:       "Model",
							Type:        FieldTypeString,
							Description: "Model name used for semantic validation.",
							Default:     "gpt-4o-mini",
						},
					},
				},
				{
					Key:         "rules",
					Label:       "Rules",
					Type:        FieldTypeArray,
					Description: "Ordered validation rules. At least one rule is required.",
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
								Description: "Name of the tool the rule applies to. Empty applies the rule to every tool.",
							},
							{
								Key:         "validator",
								Label:       "Validator",
								Type:        FieldTypeEnum,
								Description: "Validation strategy applied to the tool call.",
								Required:    true,
								Enum:        []string{"not_in_allowed_list", "json_schema", "semantic", "regex", "denylist"},
							},
							{
								Key:         "argument_path",
								Label:       "Argument Path",
								Type:        FieldTypeString,
								Description: "JSONPath into the tool call arguments. Only used by the regex and denylist validators.",
							},
							{
								Key:         "pattern",
								Label:       "Pattern",
								Type:        FieldTypeString,
								Description: "Regular expression the argument value must match. Required for the regex validator.",
							},
							{
								Key:         "denylist",
								Label:       "Denylist",
								Type:        FieldTypeArray,
								Description: "Forbidden substrings. Required for the denylist validator.",
								Item:        &Field{Key: "value", Label: "Value", Type: FieldTypeString},
							},
							{
								Key:         "behavior",
								Label:       "Behavior",
								Type:        FieldTypeEnum,
								Description: "Action taken when the rule matches. Redact, mask, and replace_with apply only to the regex and denylist validators.",
								Enum:        []string{"reject_response", "redact", "mask", "replace_with"},
								Default:     "reject_response",
							},
							{
								Key:         "redact_with",
								Label:       "Redact With",
								Type:        FieldTypeString,
								Description: "Replacement value used by the redact, mask, and replace_with behaviors.",
							},
						},
					},
				},
			},
		},
	},
	"prompt_template": {
		name:        "Prompt Template",
		group:       groupOther,
		description: "Inject context-bound system prompts (Mode A) and/or render client-referenced named, versioned templates (Mode B) into the request before it reaches the model.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "template_engine",
					Label:       "Template Engine",
					Type:        FieldTypeEnum,
					Description: "Placeholder rendering engine. Only mustache is supported in v1.",
					Enum:        []string{"mustache", "jinja2_subset"},
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
								Enum:        []string{"header", "jwt_claim"},
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
								Enum:        []string{"system"},
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
								Enum:        []string{"merge", "replace"},
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
											Key:         "version",
											Label:       "Version",
											Type:        FieldTypeString,
											Description: "Unique version identifier within the template.",
											Required:    true,
										},
										{
											Key:         "labels",
											Label:       "Labels",
											Type:        FieldTypeArray,
											Description: "Labels that resolve to this version (e.g. stable).",
											Item:        &Field{Key: "label", Label: "Label", Type: FieldTypeString},
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
														Enum:        []string{"string", "number", "boolean"},
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
					Enum:        []string{"error", "empty_string", "skip_injection"},
					Default:     "error",
				},
				{
					Key:         "on_missing_client_variable",
					Label:       "On Missing Client Variable",
					Type:        FieldTypeEnum,
					Description: "Behavior when a non-required client variable is absent.",
					Enum:        []string{"error", "empty_string"},
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
	"tool_definition_transformation": {
		name:        "Tool Definition Transformation",
		group:       groupOther,
		description: "Reshape tool definitions on the request leg before they reach the model: patch a matched tool's JSON schema, override its description, and inject operator-authored tools. This is a governance and steering layer, not an access gate.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "transform_tools",
					Label:       "Transform Tools",
					Type:        FieldTypeArray,
					Description: "Rules applied to matching client tools. All matching rules apply in declaration order; schema patches accrue and the last description override wins.",
					Item: &Field{
						Key:   "transform",
						Label: "Transform",
						Type:  FieldTypeObject,
						Fields: []Field{
							{
								Key:         "tool",
								Label:       "Tool",
								Type:        FieldTypeString,
								Description: "Glob pattern matched against the tool name (e.g. search_*).",
								Required:    true,
							},
							{
								Key:         "schema_patch",
								Label:       "Schema Patch",
								Type:        FieldTypeObject,
								Description: "RFC 7386 JSON merge patch applied to the matched tool's parameter schema. Free-form JSON; edited as a raw object.",
							},
							{
								Key:         "description_override",
								Label:       "Description Override",
								Type:        FieldTypeString,
								Description: "Replacement description for the matched tool.",
							},
						},
					},
				},
				{
					Key:         "inject_tools",
					Label:       "Inject Tools",
					Type:        FieldTypeArray,
					Description: "Operator-authored tools appended to the request. Name collisions are resolved by the on_conflict policy.",
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
								Enum:        []string{"function"},
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
					Enum:        []string{"gateway_wins", "client_wins", "reject"},
					Default:     "gateway_wins",
				},
				{
					Key:         "scope",
					Label:       "Scope",
					Type:        FieldTypeEnum,
					Description: "Informational; effective scope derives from the policy global flag.",
					Enum:        []string{"consumer", "global"},
				},
			},
		},
	},
	"trustguard": {
		name:        "TrustGuard",
		group:       groupOther,
		description: "Inspect request and/or response content with the external TrustGuard guardrail service and block content it flags. Fails open on any transport error, timeout, non-2xx response, or missing base URL. Streaming responses cannot be blocked in realtime.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "api_key",
					Label:       "API Key",
					Type:        FieldTypeString,
					Description: "Credential sent as a Bearer token to the TrustGuard service.",
					Required:    true,
				},
				{
					Key:         "consumer_id",
					Label:       "Consumer ID",
					Type:        FieldTypeString,
					Description: "Identifier forwarded to TrustGuard to attribute the guarded call.",
					Required:    true,
				},
				{
					Key:         "inspect",
					Label:       "Inspect",
					Type:        FieldTypeEnum,
					Description: "Which legs to inspect: the request, the response, or both.",
					Enum:        []string{"request", "response", "request_response"},
					Default:     "request_response",
				},
				{
					Key:         "base_url",
					Label:       "Base URL",
					Type:        FieldTypeString,
					Description: "Optional per-policy override of the TrustGuard base URL. Falls back to the gateway TRUSTGUARD_BASE_URL when empty.",
				},
			},
		},
	},
}
