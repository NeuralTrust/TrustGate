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
	"net/url"
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
)

type Settings struct {
	Inspect     string `mapstructure:"inspect"`
	BaseURL     string `mapstructure:"base_url"`
	CollectorID string `mapstructure:"collector_id"`
}

func parseConfig(settings map[string]any) (Settings, error) {
	cfg, err := pluginutil.Parse[Settings](settings)
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
}

func (s *Settings) validate() error {
	switch s.Inspect {
	case inspectRequest, inspectResponse, inspectRequestResponse:
	default:
		return fmt.Errorf("trustguard: inspect must be one of request, response, request_response")
	}
	if s.BaseURL != "" {
		parsed, err := url.Parse(s.BaseURL)
		if err != nil {
			return fmt.Errorf("trustguard: base_url is invalid: %w", err)
		}
		if !parsed.IsAbs() || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return fmt.Errorf("trustguard: base_url must be an absolute http(s) url")
		}
	}
	if strings.TrimSpace(s.CollectorID) == "" {
		return fmt.Errorf("trustguard: collector_id is required")
	}
	if _, err := uuid.Parse(strings.TrimSpace(s.CollectorID)); err != nil {
		return fmt.Errorf("trustguard: collector_id must be a valid UUID")
	}
	return nil
}

func (s Settings) selectsStage(stage policy.Stage) bool {
	switch s.Inspect {
	case inspectRequest:
		return stage == policy.StagePreRequest
	case inspectResponse:
		return stage == policy.StagePreResponse
	case inspectRequestResponse:
		return stage == policy.StagePreRequest || stage == policy.StagePreResponse
	default:
		return false
	}
}
