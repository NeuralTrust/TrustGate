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

import (
	"maps"
	"slices"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

// ResolveHeaders merges an incoming static header map with the stored one,
// key by key. Header values are read masked, so a value equal to the masked
// form of the stored value (secret.Mask, header names matched
// case-insensitively, as HTTP header names are) keeps the stored value. Any
// other masked value is left as is, and validation refuses it: an edit of the
// visible tail must not be dropped silently. Every other value replaces the
// stored one, keys only in incoming are added and keys missing from incoming
// are dropped. A nil incoming map is returned as is: callers decide whether it
// means "keep" or "clear".
func ResolveHeaders(incoming, stored map[string]string) map[string]string {
	out, _ := resolveHeaders(incoming, stored, nil)
	return out
}

// resolveHeaders is ResolveHeaders that also carries the read-time marks of
// headers whose stored value could not be decrypted: such a header sent back
// empty or masked stays empty and marked, so the repository keeps what is
// stored. It returns the marked names in order.
func resolveHeaders(incoming, stored map[string]string, unreadable []string) (map[string]string, []string) {
	if incoming == nil {
		return nil, nil
	}
	out := make(map[string]string, len(incoming))
	var marked []string
	for key, value := range incoming {
		if (value == "" || secret.IsMasked(value)) && containsFold(unreadable, key) {
			out[key] = ""
			marked = append(marked, key)
			continue
		}
		if secret.IsMasked(value) {
			if prev, ok := storedHeader(stored, key); ok && value == secret.Mask(prev) {
				value = prev
			}
		}
		out[key] = value
	}
	slices.Sort(marked)
	return out, marked
}

func containsFold(names []string, key string) bool {
	return slices.ContainsFunc(names, func(name string) bool { return strings.EqualFold(name, key) })
}

func storedHeader(stored map[string]string, key string) (string, bool) {
	if v, ok := stored[key]; ok {
		return v, true
	}
	for _, k := range slices.Sorted(maps.Keys(stored)) {
		if strings.EqualFold(k, key) {
			return stored[k], true
		}
	}
	return "", false
}

// maskedHeader returns the first header, in name order, whose value is still a
// masked placeholder after merging: it matched no stored value.
func maskedHeader(headers map[string]string) (string, bool) {
	for _, k := range slices.Sorted(maps.Keys(headers)) {
		if secret.IsMasked(headers[k]) {
			return k, true
		}
	}
	return "", false
}
