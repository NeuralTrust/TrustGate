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

package llmcost

import (
	"strings"

	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// DowngradeHeader flags a response whose model was downgraded, carrying the
// "original→target" transition as its value.
const DowngradeHeader = "X-NeuralTrust-Model-Downgraded"

const downgradeArrow = "→"

// ResolveDowngrade validates a downgrade target against the request provider and
// the allowed models, returning the bare target model when it is usable.
func ResolveDowngrade(provider, target string, allowed []string) (string, bool) {
	intent, err := routingdomain.ParseModelRef(target)
	if err != nil {
		return "", false
	}
	if intent.PoolAlias != "" || intent.Model == "" {
		return "", false
	}
	if intent.Provider != "" && !strings.EqualFold(intent.Provider, provider) {
		return "", false
	}
	if len(allowed) > 0 && !modelAllowed(intent.Model, allowed) {
		return "", false
	}
	return intent.Model, true
}

func modelAllowed(model string, allowed []string) bool {
	for _, m := range allowed {
		if m == model {
			return true
		}
	}
	return false
}

// ApplyDowngrade rewrites the request body to target when the downgrade is
// valid, returning the new model, the rewritten body, and the downgrade header.
func ApplyDowngrade(req *infracontext.RequestContext, orig, target string) (string, []byte, map[string][]string, bool) {
	if req == nil {
		return "", nil, nil, false
	}
	newModel, ok := ResolveDowngrade(req.Provider, target, req.AllowedModels)
	if !ok {
		return "", nil, nil, false
	}
	body := adapter.OverrideModel(req.Body, newModel)
	headers := map[string][]string{
		DowngradeHeader: {orig + downgradeArrow + newModel},
	}
	return newModel, body, headers, true
}
