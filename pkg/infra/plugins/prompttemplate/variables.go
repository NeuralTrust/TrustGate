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

package prompttemplate

import (
	"sort"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

func resolveContextVars(cfg *config, req *infracontext.RequestContext) (map[string]string, []string) {
	resolved := make(map[string]string, len(cfg.ContextVariables))
	missing := make([]string, 0)
	for key, spec := range cfg.ContextVariables {
		value, ok := resolveOne(spec, req)
		if !ok || value == "" {
			missing = append(missing, key)
			continue
		}
		resolved[key] = value
	}
	sort.Strings(missing)
	return resolved, missing
}

func resolveOne(spec contextVar, req *infracontext.RequestContext) (string, bool) {
	switch spec.Source {
	case sourceHeader:
		value := req.HeaderValue(spec.Name)
		return value, value != ""
	case sourceJWTClaim:
		return unverifiedClaim(bearerToken(req), spec.Name)
	default:
		return "", false
	}
}
