package config

// ProviderConfig represents the configuration for a single provider
type ProviderConfig struct {
	Name      string                    `mapstructure:"name"`
	BaseURL   string                    `mapstructure:"base_url"`
	Endpoints map[string]EndpointConfig `mapstructure:"endpoints"`
}

type EndpointConfig struct {
	Path   string          `mapstructure:"path"`
	Schema *ProviderSchema `mapstructure:"schema,omitempty"`
}

type ProviderSchema struct {
	IdentifyingKeys []string               `mapstructure:"identifying_keys"`
	RequestFormat   map[string]SchemaField `mapstructure:"request_format"`
	ResponseFormat  map[string]SchemaField `mapstructure:"response_format"`
}

type SchemaField struct {
	Type      string      `mapstructure:"type"` // string, array, object, number, boolean
	Required  bool        `mapstructure:"required"`
	Path      string      `mapstructure:"path"` // JSON path for mapping
	Default   interface{} `mapstructure:"default,omitempty"`
	Condition string      `mapstructure:"condition,omitempty"` // Condition for extracting value
}

// ProvidersConfig represents the configuration for all providers
type ProvidersConfig struct {
	Providers map[string]ProviderConfig `mapstructure:"providers"`
}
