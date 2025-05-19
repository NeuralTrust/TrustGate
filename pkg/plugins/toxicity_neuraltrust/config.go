package toxicity_neuraltrust

type Config struct {
	Credentials      Credentials       `mapstructure:"credentials"`
	ToxicityParamBag *ToxicityParamBag `mapstructure:"toxicity"`
	MappingField     string            `mapstructure:"mapping_field"`
	RetentionPeriod  int               `mapstructure:"retention_period"`
}

type Credentials struct {
	BaseURL string `mapstructure:"base_url"`
	Token   string `mapstructure:"token"`
}

type ToxicityParamBag struct {
	Threshold float64 `mapstructure:"threshold"`
}
