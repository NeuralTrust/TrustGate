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

package openaicompat

import (
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func upstreamHeaders(creds providers.Credentials, opts providers.OpenAICompatibleOptions) map[string]string {
	if len(creds.Headers) == 0 && len(opts.Headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(creds.Headers)+len(opts.Headers))
	for k, v := range creds.Headers {
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	for k, v := range opts.Headers {
		if k == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func applyUpstreamAuth(req *http.Request, apiKey string, headers map[string]string) {
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	for k, v := range headers {
		if k == "" {
			continue
		}
		req.Header.Set(k, v)
	}
}
