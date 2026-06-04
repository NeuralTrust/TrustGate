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
		description: "Limit request volume using sliding windows scoped globally or per user, IP or fingerprint.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "limits",
					Label:       "Limits",
					Type:        FieldTypeMap,
					Description: "Per-scope request limits. At least one scope must be configured.",
					Required:    true,
					KeyOptions:  []string{"global", "per_user", "per_ip", "per_fingerprint"},
					Value: &Field{
						Key:   "limit",
						Label: "Limit",
						Type:  FieldTypeObject,
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
						},
					},
				},
				{
					Key:         "actions",
					Label:       "Actions",
					Type:        FieldTypeObject,
					Description: "Behaviour applied when a limit is exceeded.",
					Fields: []Field{
						{
							Key:         "type",
							Label:       "Action Type",
							Type:        FieldTypeEnum,
							Description: "How to respond when the limit is exceeded.",
							Enum:        []string{"reject", "block"},
							Default:     "reject",
						},
						{
							Key:         "retry_after",
							Label:       "Retry After",
							Type:        FieldTypeString,
							Description: "Value sent in the Retry-After header, in seconds.",
							Default:     "60",
						},
					},
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
		name:        "Token Rate Limiter",
		group:       groupQuota,
		description: "Enforce an LLM token budget per identifier over a fixed time window.",
		schema: SettingsSchema{
			Fields: []Field{
				{
					Key:         "identifier_header",
					Label:       "Identifier Header",
					Type:        FieldTypeString,
					Description: "Request header used to identify the caller. Falls back to a shared budget when empty.",
				},
				{
					Key:      "window",
					Label:    "Window",
					Type:     FieldTypeObject,
					Required: true,
					Fields: []Field{
						{
							Key:         "unit",
							Label:       "Unit",
							Type:        FieldTypeEnum,
							Description: "Time unit of the budget window.",
							Required:    true,
							Enum:        []string{"second", "minute", "hour", "day"},
						},
						{
							Key:         "max",
							Label:       "Max Tokens",
							Type:        FieldTypeInteger,
							Description: "Maximum number of tokens allowed within the window.",
							Required:    true,
						},
					},
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
}
