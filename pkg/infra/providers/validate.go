package providers

func ValidateProviderOptions(provider string, options map[string]any) error {
	switch provider {
	case ProviderOpenAICompatible:
		_, err := DecodeOpenAICompatibleOptions(options)
		return err
	default:
		return nil
	}
}
