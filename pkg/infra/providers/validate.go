package providers

func ValidateProviderOptions(provider string, options map[string]any) error {
	switch provider {
	case ProviderOpenAICompatible:
		_, err := DecodeOpenAICompatibleOptions(options)
		return err
	case ProviderOpenAI:
		_, err := DecodeOpenAIOptions(options)
		return err
	case ProviderVertex:
		_, err := DecodeVertexOptions(options)
		return err
	default:
		return nil
	}
}
