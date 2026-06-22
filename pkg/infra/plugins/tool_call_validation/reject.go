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
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const (
	typeToolNotInList            = "tool_not_in_list"
	typeToolSchemaInvalid        = "tool_schema_invalid"
	typeToolSemanticBlocked      = "tool_semantic_blocked"
	typeToolCallValidationFailed = "tool_call_validation_failed"
)

func rejectStatus(rejectType string) int {
	switch rejectType {
	case typeToolNotInList, typeToolSchemaInvalid, typeToolSemanticBlocked:
		return http.StatusForbidden
	case typeToolCallValidationFailed:
		return http.StatusBadGateway
	default:
		return http.StatusForbidden
	}
}

func newViolation(rejectType, message string) violation {
	return violation{
		matched:    true,
		rejectType: rejectType,
		status:     rejectStatus(rejectType),
		message:    message,
	}
}

func newPluginError(v violation) *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: v.status,
		Type:       v.rejectType,
		Message:    v.message,
	}
}
