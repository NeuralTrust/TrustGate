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

package telemetry

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type Telemetry struct {
	Exporters           []ExporterConfig  `json:"exporters"`
	ExtraParams         map[string]string `json:"extra_params"`
	EnablePluginTraces  bool              `json:"enable_plugin_traces"`
	EnableRequestTraces bool              `json:"enable_request_traces"`
	HeaderMapping       map[string]string `json:"header_mapping"`
}

type ExporterConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`
	Settings map[string]interface{} `json:"settings"`
}

func (c ExporterConfig) EffectiveType() string {
	if c.Type != "" {
		return c.Type
	}
	return c.Name
}

func (t Telemetry) Value() (driver.Value, error) {
	return json.Marshal(t)
}

func (t *Telemetry) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("could not convert value %v to []byte", value)
	}
	return json.Unmarshal(bytes, t)
}
