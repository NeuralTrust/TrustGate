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

package request

import (
	"encoding/json"
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// SR1ConfigRequest declares session lifetime and the optional quality upgrade.
type SR1ConfigRequest struct {
	CacheTTLSeconds    int  `json:"cache_ttl_seconds" minimum:"1" maximum:"86400"`
	EscapeHatchEnabled bool `json:"escape_hatch_enabled"`
}

// UnmarshalJSON requires an explicit boolean when the escape-hatch field is sent.
func (r *SR1ConfigRequest) UnmarshalJSON(raw []byte) error {
	type wire SR1ConfigRequest
	var decoded wire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for name, value := range fields {
		if strings.EqualFold(name, "escape_hatch_enabled") && strings.TrimSpace(string(value)) == "null" {
			return fmt.Errorf("escape_hatch_enabled must be a boolean: %w", commonerrors.ErrValidation)
		}
	}
	*r = SR1ConfigRequest(decoded)
	return nil
}
