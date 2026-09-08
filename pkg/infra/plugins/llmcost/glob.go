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

// Package llmcost holds the model-pricing primitives shared by the LLM budget
// and cost cap plugins: glob matching of model slugs, price resolution, model
// downgrade, and the stateless cost cap decision engine.
package llmcost

import (
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
)

func GlobMatch(pattern, s string) bool {
	return modelmatch.Matches(pattern, s)
}

// BestMatch returns the value whose key best matches s. An exact key wins over
// any glob; among globs the most specific pattern (most literal characters)
// wins, ties broken lexicographically.
func BestMatch[T any](m map[string]T, s string) (T, bool) {
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
		if !strings.Contains(pattern, "*") || !GlobMatch(pattern, s) {
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
