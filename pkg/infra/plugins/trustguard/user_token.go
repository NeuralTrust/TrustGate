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

package trustguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const typeUserTokenRefused = "trustguard_user_token_rejected"

// userTokenCodes are the error codes TrustGuard answers when the end user's token (or the user it
// names) is refused. user_token_unavailable (503, the identity provider's keys are down) is not here:
// that is availability and follows failure_mode.
var userTokenCodes = map[string]struct{}{
	"user_token_not_configured": {},
	"invalid_user_token":        {},
	"user_mismatch":             {},
	"asset_conflict":            {},
	"user_token_required":       {},
}

// userTokenRefusedError is TrustGuard refusing the end user's token. It blocks whatever the
// failure_mode, and never touches the service token.
type userTokenRefusedError struct {
	status int
	code   string
}

func (e *userTokenRefusedError) Error() string {
	return fmt.Sprintf("trustguard: user token refused status %d (%s)", e.status, e.code)
}

// userTokenRefusalOf classifies a 400, 401 or 403 answer by TrustGuard's error code alone, whatever the
// status. An answer without one (a service-side 403, say) is never a refusal of the user's token.
func userTokenRefusalOf(status int, raw []byte) *userTokenRefusedError {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
	default:
		return nil
	}
	var envelope struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &envelope)
	if _, ok := userTokenCodes[envelope.Code]; ok {
		return &userTokenRefusedError{status: status, code: envelope.Code}
	}
	return nil
}

func userTokenRefusal(err error) *userTokenRefusedError {
	var refused *userTokenRefusedError
	if errors.As(err, &refused) {
		return refused
	}
	return nil
}

func userTokenRefusedPluginError(e *userTokenRefusedError) *appplugins.PluginError {
	message := "request refused: the end user's token was not accepted"
	body, _ := json.Marshal(map[string]string{
		"status":  statusBlock,
		"type":    typeUserTokenRefused,
		"code":    e.code,
		"message": message,
	})
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       typeUserTokenRefused,
		Message:    message,
		Body:       body,
	}
}
