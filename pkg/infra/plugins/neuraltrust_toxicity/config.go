package neuraltrust_toxicity

type Config struct {
	Provider         string            `mapstructure:"provider"`
	Credentials      Credentials       `mapstructure:"credentials"`
	ToxicityParamBag *ToxicityParamBag `mapstructure:"toxicity"`
	MappingField     string            `mapstructure:"mapping_field"`
	RetentionPeriod  int               `mapstructure:"retention_period"`
}

type Credentials struct {
	NeuralTrust *NeuralTrustCredentials `mapstructure:"neuraltrust"`
	OpenAI      *OpenAICredentials      `mapstructure:"openai"`

	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
	APIKey  string `mapstructure:"openai_api_key"`
}

type NeuralTrustCredentials struct {
	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
}

type OpenAICredentials struct {
	APIKey string `mapstructure:"api_key"`
}

type ToxicityParamBag struct {
	Threshold float64 `mapstructure:"threshold"`
}
