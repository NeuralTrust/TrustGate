package neuraltrust_jailbreak

type Config struct {
	Provider          string             `mapstructure:"provider"`
	Credentials       Credentials        `mapstructure:"credentials"`
	JailbreakParamBag *JailbreakParamBag `mapstructure:"jailbreak"`
	MappingField      string             `mapstructure:"mapping_field"`
	RetentionPeriod   int                `mapstructure:"retention_period"`
	Mode              string             `mapstructure:"mode"`
}

type Credentials struct {
	NeuralTrust *NeuralTrustCredentials `mapstructure:"neuraltrust"`
	OpenAI      *OpenAICredentials      `mapstructure:"openai"`

	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
	APIKey  string `mapstructure:"openai_api_key"` // #nosec G117 -- Plugin config field for OpenAI API key
}

type NeuralTrustCredentials struct {
	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
}

type OpenAICredentials struct {
	APIKey string `mapstructure:"api_key"` // #nosec G117 -- Plugin config field for OpenAI API key
}

type JailbreakParamBag struct {
	Threshold float64 `mapstructure:"threshold"`
}
