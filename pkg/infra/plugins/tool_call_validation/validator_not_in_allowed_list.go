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

type notInAllowedListValidator struct{}

func (notInAllowedListValidator) Evaluate(_ context.Context, in validatorInput) (violation, error) {
	if in.eval == nil || len(in.eval.allowed) == 0 {
		return violation{}, nil
	}
	if _, ok := in.eval.allowed[in.toolCall.Name]; ok {
		return violation{}, nil
	}
	return newViolation(typeToolNotInList, fmt.Sprintf("tool %q is not in the allowed list", in.toolCall.Name)), nil
}
