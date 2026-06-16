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

package registry

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type HealthChecks struct {
	Passive   bool              `json:"passive"`
	Path      string            `json:"path,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Threshold int               `json:"threshold"`
	Interval  int               `json:"interval"`
}

func (h *HealthChecks) Validate() error {
	if h.Interval <= 0 {
		return fmt.Errorf("%w: health_checks.interval must be positive", ErrInvalidHealthChecks)
	}
	if h.Threshold <= 0 {
		return fmt.Errorf("%w: health_checks.threshold must be positive", ErrInvalidHealthChecks)
	}
	return nil
}

func (h HealthChecks) Value() (driver.Value, error) {
	return json.Marshal(h)
}

func (h *HealthChecks) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, h)
}
