package providers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/mitchellh/mapstructure"
)

const (
	OpenAIAPICompletions = "completions"
	OpenAIAPIResponses   = "responses"

	vertexDefaultAPIVersion = "v1"
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
	if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
		return OpenAICompatibleOptions{}, fmt.Errorf("openai_compatible: %w", err)
	}

	return opts, nil
}

type OpenAIOptions struct {
	API     string `mapstructure:"api"`
	BaseURL string `mapstructure:"base_url"`
}

func DecodeOpenAIOptions(options map[string]any) (OpenAIOptions, error) {
	var opts OpenAIOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return OpenAIOptions{}, fmt.Errorf("openai: invalid provider_options: %w", err)
		}
	}

	opts.API = strings.TrimSpace(opts.API)
	switch opts.API {
	case "", OpenAIAPICompletions, OpenAIAPIResponses:
	default:
		return OpenAIOptions{}, fmt.Errorf("openai: provider_options.api must be %q or %q, got %q", OpenAIAPICompletions, OpenAIAPIResponses, opts.API)
	}

	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL != "" {
		if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
			return OpenAIOptions{}, fmt.Errorf("openai: %w", err)
		}
	}

	return opts, nil
}

type VertexOptions struct {
	Project  string `mapstructure:"project"`
	Location string `mapstructure:"location"`
	Version  string `mapstructure:"version"`
}

func DecodeVertexOptions(options map[string]any) (VertexOptions, error) {
	var opts VertexOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return VertexOptions{}, fmt.Errorf("vertex: invalid provider_options: %w", err)
		}
	}

	opts.Project = strings.TrimSpace(opts.Project)
	opts.Location = strings.TrimSpace(opts.Location)
	opts.Version = strings.TrimSpace(opts.Version)

	if opts.Project == "" {
		return VertexOptions{}, fmt.Errorf("vertex: provider_options.project is required")
	}
	if opts.Location == "" {
		return VertexOptions{}, fmt.Errorf("vertex: provider_options.location is required")
	}
	if opts.Version == "" {
		opts.Version = vertexDefaultAPIVersion
	}

	return opts, nil
}

func validateHTTPBaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("base_url must be a valid http(s) URL, got %q", raw)
	}
	return nil
}
