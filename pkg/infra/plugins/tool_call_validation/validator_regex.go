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
	"regexp"
)

type regexValidator struct{}

func (regexValidator) Evaluate(_ context.Context, in validatorInput) (violation, error) {
	value, ok := stringArgumentValue(in.toolCall.Arguments, in.rule.ArgumentPath)
	if !ok {
		return violation{}, nil
	}
	re, err := regexp.Compile(`\A(?:` + in.rule.Pattern + `)\z`)
	if err != nil {
		return violation{}, nil
	}
	if re.MatchString(value) {
		return violation{}, nil
	}
	return violation{matched: true, matchedValue: value}, nil
}
