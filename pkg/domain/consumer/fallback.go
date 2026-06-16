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

package consumer

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

type FallbackTrigger string

const (
	TriggerHTTP5xx       FallbackTrigger = "http_5xx"
	TriggerHTTP429       FallbackTrigger = "http_429"
	TriggerTimeout       FallbackTrigger = "timeout"
	TriggerProviderError FallbackTrigger = "provider_error"
	TriggerPluginReject  FallbackTrigger = "plugin_rejection"
)

func (t FallbackTrigger) IsValid() bool {
	switch t {
	case TriggerHTTP5xx, TriggerHTTP429, TriggerTimeout, TriggerProviderError, TriggerPluginReject:
		return true
	}
	return false
}

type FallbackBudget struct {
	MaxAttempts     int           `json:"max_attempts"`
	MaxTotalLatency time.Duration `json:"max_total_latency,omitempty"`
}

type Fallback struct {
	Enabled  bool                `json:"enabled"`
	Triggers []FallbackTrigger   `json:"triggers,omitempty"`
	Budget   FallbackBudget      `json:"budget"`
	Chain    registry.Registries `json:"chain,omitempty"`
}

func (f Fallback) Value() (driver.Value, error) {
	return json.Marshal(f)
}

func (f *Fallback) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, f)
}

func (f *Fallback) HasTrigger(t FallbackTrigger) bool {
	if f == nil {
		return false
	}
	for _, trigger := range f.Triggers {
		if trigger == t {
			return true
		}
	}
	return false
}

func (f *Fallback) Validate() error {
	if f == nil || !f.Enabled {
		return nil
	}
	if len(f.Triggers) == 0 {
		return fmt.Errorf("%w: at least one trigger is required when enabled", ErrInvalidFallback)
	}
	for _, t := range f.Triggers {
		if !t.IsValid() {
			return fmt.Errorf("%w: unknown trigger %q", ErrInvalidFallback, t)
		}
	}
	if f.Budget.MaxAttempts < 0 {
		return fmt.Errorf("%w: budget.max_attempts cannot be negative", ErrInvalidFallback)
	}
	if f.Budget.MaxTotalLatency < 0 {
		return fmt.Errorf("%w: budget.max_total_latency cannot be negative", ErrInvalidFallback)
	}
	if len(f.Chain) == 0 {
		return fmt.Errorf("%w: chain requires at least one backend when enabled", ErrInvalidFallback)
	}
	if err := f.Chain.Validate(); err != nil {
		return fmt.Errorf("%w: invalid chain: %s", ErrInvalidFallback, err.Error())
	}
	return nil
}
