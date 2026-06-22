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
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
)

type jsonSchemaValidator struct{}

func (jsonSchemaValidator) Evaluate(in validatorInput) (violation, error) {
	if in.eval == nil {
		return violation{}, nil
	}
	tool, ok := in.eval.toolByName[in.toolCall.Name]
	if !ok || len(tool.Schema) == 0 {
		return violation{}, nil
	}
	raw, err := json.Marshal(tool.Schema)
	if err != nil {
		return violation{}, nil
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return violation{}, nil
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{})
	if err != nil {
		return violation{}, nil
	}
	var instance any
	if err := json.Unmarshal([]byte(in.toolCall.Arguments), &instance); err != nil {
		return violation{}, nil
	}
	if err := resolved.Validate(instance); err != nil {
		return newViolation(typeToolSchemaInvalid, fmt.Sprintf("tool %q arguments failed schema validation", in.toolCall.Name)), nil
	}
	return violation{}, nil
}
