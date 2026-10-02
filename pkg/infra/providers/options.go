// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package providers

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"
)

const (
	OpenAIAPICompletions = "completions"
	OpenAIAPIResponses   = "responses"
	AzureAPIDeployments  = "deployments"
	AzureAPIOpenAIV1     = "openai_v1"
	AzureAPIResponses    = "responses"
	AzureAPIAnthropic    = "anthropic"

	vertexDefaultAPIVersion = "v1"
)

type AzureOptions struct {
	API string `mapstructure:"api"`
}

func DecodeAzureOptions(options map[string]any) (AzureOptions, error) {
	var opts AzureOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return AzureOptions{}, fmt.Errorf("azure: invalid provider_options: %w", err)
		}
	}

	opts.API = strings.TrimSpace(opts.API)
	switch opts.API {
	case "", AzureAPIDeployments:
		opts.API = AzureAPIDeployments
	case AzureAPIOpenAIV1, AzureAPIResponses, AzureAPIAnthropic:
	default:
		return AzureOptions{}, fmt.Errorf(
			"azure: provider_options.api must be %q, %q, %q, or %q, got %q",
			AzureAPIDeployments,
			AzureAPIOpenAIV1,
			AzureAPIResponses,
			AzureAPIAnthropic,
			opts.API,
		)
	}
	return opts, nil
}

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
	BaseURL  string `mapstructure:"base_url"`
}

// vertexLocationPattern matches a GCP region (us-central1, europe-west4), a
// multi-region (us, eu) or global. It has no dot, slash, colon, '@', '#', '?'
// or '%', so it cannot change the host it is put in.
var vertexLocationPattern = regexp.MustCompile(`^[a-z]+(-[a-z]+)*[0-9]*$`)

func DecodeVertexOptions(options map[string]any) (VertexOptions, error) {
	var opts VertexOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return VertexOptions{}, fmt.Errorf("vertex: invalid provider_options: %w", err)
		}
	}

	opts.Project = strings.TrimSpace(opts.Project)
	// The location reaches both the host and the URL path, where mixed case would not resolve.
	opts.Location = strings.ToLower(strings.TrimSpace(opts.Location))
	opts.Version = strings.TrimSpace(opts.Version)

	if opts.Project == "" {
		return VertexOptions{}, fmt.Errorf("vertex: provider_options.project is required")
	}
	if opts.Location == "" {
		return VertexOptions{}, fmt.Errorf("vertex: provider_options.location is required")
	}
	// The location is interpolated into the HOST of a credentialed request, so a value that can change the host is a token leak, not a typo.
	if !vertexLocationPattern.MatchString(opts.Location) {
		return VertexOptions{}, fmt.Errorf(
			"vertex: provider_options.location must be a GCP region or multi-region such as us-central1, eu or global",
		)
	}
	if opts.Version == "" {
		opts.Version = vertexDefaultAPIVersion
	}

	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL != "" {
		if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
			return VertexOptions{}, fmt.Errorf("vertex: %w", err)
		}
	}

	return opts, nil
}

type CohereOptions struct {
	BaseURL string `mapstructure:"base_url"`
}

type MistralOptions struct {
	BaseURL string `mapstructure:"base_url"`
}

type AnthropicOptions struct {
	BaseURL string `mapstructure:"base_url"`
}

func DecodeAnthropicOptions(options map[string]any) (AnthropicOptions, error) {
	var opts AnthropicOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return AnthropicOptions{}, fmt.Errorf("anthropic: invalid provider_options: %w", err)
		}
	}
	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL != "" {
		if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
			return AnthropicOptions{}, fmt.Errorf("anthropic: %w", err)
		}
	}
	return opts, nil
}

type GroqOptions struct {
	BaseURL string `mapstructure:"base_url"`
}

type OpenRouterOptions struct {
	BaseURL string `mapstructure:"base_url"`
}

func DecodeGroqOptions(options map[string]any) (GroqOptions, error) {
	var opts GroqOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return GroqOptions{}, fmt.Errorf("groq: invalid provider_options: %w", err)
		}
	}
	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL != "" {
		if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
			return GroqOptions{}, fmt.Errorf("groq: %w", err)
		}
	}
	return opts, nil
}

func DecodeOpenRouterOptions(options map[string]any) (OpenRouterOptions, error) {
	var opts OpenRouterOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return OpenRouterOptions{}, fmt.Errorf("openrouter: invalid provider_options: %w", err)
		}
	}
	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL != "" {
		if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
			return OpenRouterOptions{}, fmt.Errorf("openrouter: %w", err)
		}
	}
	return opts, nil
}

func DecodeMistralOptions(options map[string]any) (MistralOptions, error) {
	var opts MistralOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return MistralOptions{}, fmt.Errorf("mistral: invalid provider_options: %w", err)
		}
	}
	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL != "" {
		if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
			return MistralOptions{}, fmt.Errorf("mistral: %w", err)
		}
	}
	return opts, nil
}

func DecodeCohereOptions(options map[string]any) (CohereOptions, error) {
	var opts CohereOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return CohereOptions{}, fmt.Errorf("cohere: invalid provider_options: %w", err)
		}
	}
	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL != "" {
		if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
			return CohereOptions{}, fmt.Errorf("cohere: %w", err)
		}
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
