package catalog

import "github.com/NeuralTrust/AgentGateway/pkg/infra/providers"

// OptionFieldType enumerates the provider_options field kinds the admin UI can
// render when building a provider connection form.
type OptionFieldType string

const (
	OptionFieldTypeString OptionFieldType = "string"
	OptionFieldTypeEnum   OptionFieldType = "enum"
	OptionFieldTypeMap    OptionFieldType = "map"
)

// ProviderOptionField describes a single provider_options input. These are
// provider-specific connection settings unrelated to credentials (e.g. the base
// URL for an OpenAI-compatible endpoint or the GCP project for Vertex).
type ProviderOptionField struct {
	Key         string          `json:"key"`
	Label       string          `json:"label"`
	Type        OptionFieldType `json:"type"`
	Description string          `json:"description,omitempty"`
	Required    bool            `json:"required,omitempty"`
	Default     any             `json:"default,omitempty"`
	Enum        []string        `json:"enum,omitempty"`
}

// providerOptionsCatalog maps each provider code to its provider_options schema.
// Schemas are hand-authored from providers.Decode*Options so the catalog matches
// the validation applied at registry create/update time. Providers without
// extra options are omitted and resolve to an empty slice.
var providerOptionsCatalog = map[string][]ProviderOptionField{
	providers.ProviderOpenAI: {
		{
			Key:         "api",
			Label:       "API",
			Type:        OptionFieldTypeEnum,
			Description: "OpenAI API surface to target.",
			Enum:        []string{providers.OpenAIAPICompletions, providers.OpenAIAPIResponses},
		},
		{
			Key:         "base_url",
			Label:       "Base URL",
			Type:        OptionFieldTypeString,
			Description: "Optional override for the OpenAI base URL (http/https).",
		},
	},
	providers.ProviderOpenAICompatible: {
		{
			Key:         "base_url",
			Label:       "Base URL",
			Type:        OptionFieldTypeString,
			Description: "Base URL of the OpenAI-compatible endpoint (http/https).",
			Required:    true,
		},
		{
			Key:         "headers",
			Label:       "Headers",
			Type:        OptionFieldTypeMap,
			Description: "Extra HTTP headers sent with every upstream request.",
		},
	},
	providers.ProviderVertex: {
		{
			Key:         "project",
			Label:       "Project",
			Type:        OptionFieldTypeString,
			Description: "GCP project ID hosting the Vertex AI models.",
			Required:    true,
		},
		{
			Key:         "location",
			Label:       "Location",
			Type:        OptionFieldTypeString,
			Description: "GCP region of the Vertex AI endpoint (e.g. us-central1).",
			Required:    true,
		},
		{
			Key:         "version",
			Label:       "API Version",
			Type:        OptionFieldTypeString,
			Description: "Vertex AI API version.",
			Default:     "v1",
		},
	},
}

// ProviderOptions returns the provider_options schema for a provider code. It
// returns an empty (non-nil) slice for providers without extra options so the
// API always emits a JSON array.
func ProviderOptions(code string) []ProviderOptionField {
	if opts, ok := providerOptionsCatalog[code]; ok {
		return opts
	}
	return []ProviderOptionField{}
}
