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

package registry

// ProviderOptionHeaders returns provider_options.headers when every value is a
// string. A missing headers key reports false. A non-string value reports false
// so callers leave the map for the provider decoder to reject.
func ProviderOptionHeaders(options map[string]any) (map[string]string, bool) {
	if options == nil {
		return nil, false
	}
	raw, exists := options["headers"]
	if !exists || raw == nil {
		return nil, false
	}
	switch headers := raw.(type) {
	case map[string]string:
		return headers, true
	case map[string]any:
		out := make(map[string]string, len(headers))
		for name, value := range headers {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			out[name] = text
		}
		return out, true
	default:
		return nil, false
	}
}

// ResolveProviderOptionHeaders merges incoming provider_options.headers with the
// stored map. A masked value that matches the stored secret is restored. A
// header marked unreadable stays empty and is returned so storage can keep the
// ciphertext. incoming is updated in place. A map without a headers key is left
// alone.
func ResolveProviderOptionHeaders(incoming, stored map[string]any, unreadable []string) []string {
	headers, ok := ProviderOptionHeaders(incoming)
	if !ok {
		return nil
	}
	storedHeaders, _ := ProviderOptionHeaders(stored)
	resolved, marked := resolveHeaders(headers, storedHeaders, unreadable)
	incoming["headers"] = resolved
	return marked
}

// MaskedProviderOptionHeader reports the first header, in name order, whose
// value is still a mask after merging.
func MaskedProviderOptionHeader(options map[string]any) (string, bool) {
	headers, ok := ProviderOptionHeaders(options)
	if !ok {
		return "", false
	}
	return maskedHeader(headers)
}
