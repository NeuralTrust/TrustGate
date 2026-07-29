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

type DatabricksOptions struct {
	BaseURL string            `mapstructure:"base_url"`
	Headers map[string]string `mapstructure:"headers"`
}

type OracleOptions struct {
	Region  string            `mapstructure:"region"`
	Project string            `mapstructure:"project"`
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

func DecodeDatabricksOptions(options map[string]any) (DatabricksOptions, error) {
	var opts DatabricksOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return DatabricksOptions{}, fmt.Errorf("databricks: invalid provider_options: %w", err)
		}
	}

	opts.BaseURL = strings.TrimSpace(opts.BaseURL)
	if opts.BaseURL == "" {
		return DatabricksOptions{}, fmt.Errorf("databricks: base_url is required")
	}
	if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
		return DatabricksOptions{}, fmt.Errorf("databricks: %w", err)
	}

	return opts, nil
}

func DecodeOracleOptions(options map[string]any) (OracleOptions, error) {
	var opts OracleOptions
	if len(options) > 0 {
		if err := mapstructure.Decode(options, &opts); err != nil {
			return OracleOptions{}, fmt.Errorf("oracle: invalid provider_options: %w", err)
		}
	}

	opts.Region = strings.TrimSpace(opts.Region)
	opts.Project = strings.TrimSpace(opts.Project)
	opts.BaseURL = strings.TrimSpace(opts.BaseURL)

	if opts.BaseURL == "" {
		if opts.Region == "" {
			return OracleOptions{}, fmt.Errorf("oracle: region or base_url is required")
		}
		opts.BaseURL = fmt.Sprintf(
			"https://inference.generativeai.%s.oci.oraclecloud.com/openai/v1",
			opts.Region,
		)
	}
	if err := validateHTTPBaseURL(opts.BaseURL); err != nil {
		return OracleOptions{}, fmt.Errorf("oracle: %w", err)
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

type CohereOptions struct {
	BaseURL string `mapstructure:"base_url"`
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
