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

package tool_call_validation

import (
	"context"
	"fmt"
)

type semanticValidator struct{}

func (semanticValidator) Evaluate(ctx context.Context, in validatorInput) (violation, error) {
	if in.eval == nil || in.eval.semantic == nil || in.eval.llm == nil {
		return violation{}, nil
	}
	if in.eval.semantic.Provider != semanticProviderOpenAI {
		return violation{}, nil
	}
	decision, reasoning, err := evaluateSemantic(
		ctx,
		in.eval.semantic,
		in.eval.llm,
		in.toolCall,
		in.eval.userPrompt,
		in.eval.reasoning,
	)
	if err != nil {
		return violation{}, nil
	}
	if decision != semanticDecisionDeny {
		return violation{}, nil
	}
	v := newViolation(typeToolSemanticBlocked, fmt.Sprintf("tool %q was blocked by semantic validation", in.toolCall.Name))
	v.reasoning = reasoning
	return v, nil
}
