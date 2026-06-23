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
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
)

func validateClientVars(version *templateVersion, properties map[string]any) error {
	names := make([]string, 0, len(version.RequiredVariables))
	for name := range version.RequiredVariables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rv := version.RequiredVariables[name]
		value, present := properties[name]
		if !present {
			return reject(http.StatusBadRequest, typeVariableMissing, fmt.Sprintf("required variable %q is missing", name))
		}
		if err := validateVarValue(name, rv, value); err != nil {
			return err
		}
	}
	return nil
}

func validateVarValue(name string, rv requiredVar, value any) error {
	switch rv.Type {
	case "string":
		s, ok := value.(string)
		if !ok {
			return reject(http.StatusBadRequest, typeVariableInvalid, fmt.Sprintf("variable %q must be a string", name))
		}
		if rv.MaxLength > 0 && len(s) > rv.MaxLength {
			return reject(http.StatusBadRequest, typeVariableInvalid, fmt.Sprintf("variable %q exceeds max_length %d", name, rv.MaxLength))
		}
		if len(rv.Enum) > 0 && !containsString(rv.Enum, s) {
			return reject(http.StatusBadRequest, typeVariableInvalid, fmt.Sprintf("variable %q is not an allowed value", name))
		}
	case "number":
		if !isNumber(value) {
			return reject(http.StatusBadRequest, typeVariableInvalid, fmt.Sprintf("variable %q must be a number", name))
		}
		if len(rv.Enum) > 0 && !containsString(rv.Enum, scalarToString(value)) {
			return reject(http.StatusBadRequest, typeVariableInvalid, fmt.Sprintf("variable %q is not an allowed value", name))
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return reject(http.StatusBadRequest, typeVariableInvalid, fmt.Sprintf("variable %q must be a boolean", name))
		}
	default:
		return reject(http.StatusBadRequest, typeVariableInvalid, fmt.Sprintf("variable %q has unsupported type %q", name, rv.Type))
	}
	return nil
}

func isNumber(value any) bool {
	switch value.(type) {
	case float64, json.Number:
		return true
	default:
		return false
	}
}

func containsString(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}
