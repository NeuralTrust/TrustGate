package providers

import "fmt"

// ValidateProviderOptions checks that provider_options carry the keys a provider
// needs before a backend is persisted. It returns nil for providers that have no
// required options. The check is intentionally lightweight (presence/type only);
// upstream connectivity is verified separately via ConnectionTester.
func ValidateProviderOptions(provider string, options map[string]any) error {
	switch provider {
	case ProviderOpenAICompatible:
		base, ok := options["base_url"].(string)
		if !ok || base == "" {
			return fmt.Errorf("provider %q requires a non-empty base_url option", provider)
		}
		return nil
	default:
		return nil
	}
}
