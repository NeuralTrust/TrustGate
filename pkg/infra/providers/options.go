package providers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/mitchellh/mapstructure"
)

type OpenAICompatibleOptions struct {
	BaseURL string            `mapstructure:"base_url"`
	Headers map[string]string `mapstructure:"headers"`
}

func DecodeOpenAICompatibleOptions(options map[string]any) (OpenAICompatibleOptions, error) {
	var opts OpenAICompatibleOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return OpenAICompatibleOptions{}, fmt.Errorf("openai_compatible: invalid provider_options: %w", err)
		}
	}

	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL == "" {
		return OpenAICompatibleOptions{}, fmt.Errorf("openai_compatible: base_url is required")
	}

	parsed, err := url.Parse(opts.BaseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return OpenAICompatibleOptions{}, fmt.Errorf("openai_compatible: base_url must be a valid http(s) URL, got %q", opts.BaseURL)
	}

	return opts, nil
}
