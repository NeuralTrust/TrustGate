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
// key by key. Header values are returned masked, so a value echoed back masked
// keeps the stored value of that header (matched case-insensitively, as HTTP
// header names are). Every other value replaces the stored one, keys only in
// incoming are added and keys missing from incoming are dropped. A nil
// incoming map is returned as is: callers decide whether it means "keep" or
// "clear".
func ResolveHeaders(incoming, stored map[string]string) map[string]string {
	if incoming == nil {
		return nil
	}
	out := make(map[string]string, len(incoming))
	for key, value := range incoming {
		if secret.IsMasked(value) {
			if prev, ok := storedHeader(stored, key); ok {
				value = prev
			}
		}
		out[key] = value
	}
	return out
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
// masked placeholder after merging: there was no stored value to keep.
func maskedHeader(headers map[string]string) (string, bool) {
	for _, k := range slices.Sorted(maps.Keys(headers)) {
		if secret.IsMasked(headers[k]) {
			return k, true
		}
	}
	return "", false
}
