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

package cohere

import (
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const defaultAPIHost = "https://api.cohere.com"

func apiHost(options map[string]any) (string, error) {
	opts, err := providers.DecodeCohereOptions(options)
	if err != nil {
		return "", err
	}
	if opts.BaseURL != "" {
		return strings.TrimRight(opts.BaseURL, "/"), nil
	}
	return defaultAPIHost, nil
}

func chatURL(options map[string]any) (string, error) {
	host, err := apiHost(options)
	if err != nil {
		return "", err
	}
	return host + "/v2/chat", nil
}

func embedURL(options map[string]any) (string, error) {
	host, err := apiHost(options)
	if err != nil {
		return "", err
	}
	return host + "/v2/embed", nil
}

func rerankURL(options map[string]any) (string, error) {
	host, err := apiHost(options)
	if err != nil {
		return "", err
	}
	return host + "/v2/rerank", nil
}

func modelsURL(options map[string]any) (string, error) {
	host, err := apiHost(options)
	if err != nil {
		return "", err
	}
	return host + "/v1/models", nil
}
