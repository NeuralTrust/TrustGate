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
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	inspectRequest         = "request"
	inspectResponse        = "response"
	inspectRequestResponse = "request_response"
	defaultInspect         = inspectRequestResponse

	onErrorFailOpen   = "fail_open"
	onErrorFailClosed = "fail_closed"
	defaultOnError    = onErrorFailOpen
)

type Settings struct {
	Inspect     string `mapstructure:"inspect"`
	CollectorID string `mapstructure:"collector_id"`
	// OnError controls transport / 5xx failure behaviour. Auth/config
	// rejections (401/403) always fail closed regardless of this setting.
	OnError string `mapstructure:"on_error"`
}

func parseConfig(settings map[string]any) (Settings, error) {
	normalized := settings
	if _, hasInspect := settings["inspect"]; !hasInspect {
		if dir, ok := settings["direction"].(string); ok && strings.TrimSpace(dir) != "" {
			normalized = make(map[string]any, len(settings)+1)
			for k, v := range settings {
				normalized[k] = v
			}
			normalized["inspect"] = dir
		}
	}
	cfg, err := pluginutil.Parse[Settings](normalized)
	if err != nil {
		return Settings{}, err
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Settings{}, err
	}
	return cfg, nil
}

func (s *Settings) applyDefaults() {
	if s.Inspect == "" {
		s.Inspect = defaultInspect
	}
	if s.OnError == "" {
		s.OnError = defaultOnError
	}
}

func (s *Settings) validate() error {
	switch s.Inspect {
	case inspectRequest, inspectResponse, inspectRequestResponse:
	default:
		return fmt.Errorf("trustguard: inspect must be one of request, response, request_response")
	}
	switch s.OnError {
	case onErrorFailOpen, onErrorFailClosed:
	default:
		return fmt.Errorf("trustguard: on_error must be one of fail_open, fail_closed")
	}
	if strings.TrimSpace(s.CollectorID) == "" {
		return fmt.Errorf("trustguard: collector_id is required")
	}
	if _, err := uuid.Parse(strings.TrimSpace(s.CollectorID)); err != nil {
		return fmt.Errorf("trustguard: collector_id must be a valid UUID")
	}
	return nil
}

func (s Settings) failClosedOnTransport() bool {
	return s.OnError == onErrorFailClosed
}

func (s Settings) selectsStage(stage policy.Stage) bool {
	switch s.Inspect {
	case inspectRequest:
		return stage == policy.StagePreRequest
	case inspectResponse:
		return stage == policy.StagePreResponse || stage == policy.StagePostResponse
	case inspectRequestResponse:
		return stage == policy.StagePreRequest ||
			stage == policy.StagePreResponse ||
			stage == policy.StagePostResponse
	default:
		return false
	}
}
