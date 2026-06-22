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

import (
	"strings"

	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	downgradeHeader = "X-NeuralTrust-Model-Downgraded"
	downgradeArrow  = "→"
)

func resolveDowngrade(provider, target string, allowed []string) (string, bool) {
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

func applyDowngrade(req *infracontext.RequestContext, orig, target string) (string, []byte, map[string][]string, bool) {
	if req == nil {
		return "", nil, nil, false
	}
	newModel, ok := resolveDowngrade(req.Provider, target, req.AllowedModels)
	if !ok {
		return "", nil, nil, false
	}
	body := adapter.OverrideModel(req.Body, newModel)
	headers := map[string][]string{
		downgradeHeader: {orig + downgradeArrow + newModel},
	}
	return newModel, body, headers, true
}
