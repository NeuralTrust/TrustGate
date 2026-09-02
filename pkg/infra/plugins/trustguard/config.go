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
	directionRequest         = "request"
	directionResponse        = "response"
	directionRequestResponse = "request_response"
	defaultDirection         = directionRequestResponse

	onErrorFailOpen   = "fail_open"
	onErrorFailClosed = "fail_closed"
	defaultOnError    = onErrorFailOpen
)

type Settings struct {
	// Direction selects which legs to inspect: the request, the response, or
	// both. It is the only key for this axis. An older name, "inspect", carried
	// the same values and was resolved ahead of this one, which silently disabled
	// response-leg inspection on policies holding both; it is gone, and the
	// accompanying migration collapses whatever policies still store it.
	Direction   string `mapstructure:"direction"`
	CollectorID string `mapstructure:"collector_id"`
	// OnError controls transport / 5xx failure behaviour. Auth/config
	// rejections (401/403) always fail closed regardless of this setting.
	OnError string `mapstructure:"on_error"`
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
	if s.Direction == "" {
		s.Direction = defaultDirection
	}
	if s.OnError == "" {
		s.OnError = defaultOnError
	}
}

func (s *Settings) validate() error {
	switch s.Direction {
	case directionRequest, directionResponse, directionRequestResponse:
	default:
		return fmt.Errorf("trustguard: direction must be one of request, response, request_response")
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
	switch s.Direction {
	case directionRequest:
		return stage == policy.StagePreRequest
	case directionResponse:
		return stage == policy.StagePreResponse || stage == policy.StagePostResponse
	case directionRequestResponse:
		return stage == policy.StagePreRequest ||
			stage == policy.StagePreResponse ||
			stage == policy.StagePostResponse
	default:
		return false
	}
}
