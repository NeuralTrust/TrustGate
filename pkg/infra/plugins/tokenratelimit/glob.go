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

package tokenratelimit

import "strings"

func globMatch(pattern, s string) bool {
	var (
		p, str       int
		star         = -1
		strBacktrack int
	)
	for str < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == s[str]:
			p++
			str++
		case p < len(pattern) && pattern[p] == '*':
			star = p
			strBacktrack = str
			p++
		case star != -1:
			p = star + 1
			strBacktrack++
			str = strBacktrack
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func bestMatch[T any](m map[string]T, s string) (T, bool) {
	if v, ok := m[s]; ok {
		return v, true
	}

	var (
		best        T
		found       bool
		bestPattern string
		bestSpec    = -1
	)
	for pattern := range m {
		if !strings.Contains(pattern, "*") || !globMatch(pattern, s) {
			continue
		}
		spec := len(pattern) - strings.Count(pattern, "*")
		if spec > bestSpec || (spec == bestSpec && pattern < bestPattern) {
			bestSpec = spec
			bestPattern = pattern
			best = m[pattern]
			found = true
		}
	}
	return best, found
}
