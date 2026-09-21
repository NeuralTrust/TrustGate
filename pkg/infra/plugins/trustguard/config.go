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
	"time"

	"github.com/google/uuid"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	legRequest         = "request"
	legResponse        = "response"
	legRequestResponse = "request_response"
	defaultLegs        = legRequestResponse

	onErrorFailOpen   = "fail_open"
	onErrorFailClosed = "fail_closed"
	defaultOnError    = onErrorFailOpen
)

const (
	defaultStreamingHeadChars            = 400
	defaultStreamingMinCharsBetweenEvals = 2048
	defaultStreamingMaxHoldMS            = 800
	defaultStreamingMaxAccumulatedBytes  = 262144
	defaultStreamingGuardTimeout         = 2 * time.Second

	minStreamingHeadChars = 1
	maxStreamingHeadChars = 4096

	minStreamingMinCharsBetweenEvals = 256
	maxStreamingMinCharsBetweenEvals = 65536

	minStreamingMaxHoldMS = 50
	maxStreamingMaxHoldMS = 5000

	minStreamingMaxAccumulatedBytes = 4096
	// The engine's detectAll returns nil above 1 MiB, so a payload larger than
	// this is not inspected at all and nothing says so.
	maxStreamingMaxAccumulatedBytes = 1048576

	minStreamingGuardTimeout = 250 * time.Millisecond
	maxStreamingGuardTimeout = 10 * time.Second
)

type Settings struct {
	// Direction selects which legs to inspect: the request, the response, or
	// both. It is the only key for this axis — an older name, "inspect", carried
	// the same values and was resolved ahead of this one, which silently
	// disabled response-leg inspection on policies holding both. It is gone, and
	// the accompanying migration collapses whatever policies still store it.
	//
	// The key name is fixed by the policy catalog. Its values are legs, not the
	// input/output direction reported to TrustGuard per evaluate call.
	Direction   string `mapstructure:"direction"`
	CollectorID string `mapstructure:"collector_id"`
	// OnError controls transport / 5xx failure behaviour. Auth/config
	// rejections (401/403) always fail closed regardless of this setting.
	OnError   string            `mapstructure:"on_error"`
	Streaming StreamingSettings `mapstructure:"streaming"`
}

// StreamingSettings configures per-block inspection of a streaming response
// leg. There is no max_inflight key: exactly one guard call is in flight by
// construction, which is what makes the contiguous-prefix invariant hold.
type StreamingSettings struct {
	Enabled              bool `mapstructure:"enabled"`
	HeadChars            int  `mapstructure:"head_chars"`
	MinCharsBetweenEvals int  `mapstructure:"min_chars_between_evals"`
	MaxHoldMS            int  `mapstructure:"max_hold_ms"`
	MaxAccumulatedBytes  int  `mapstructure:"max_accumulated_bytes"`
	// FinalPass is a pointer so that an explicit false is distinguishable from
	// an absent key, which defaults to true.
	FinalPass    *bool  `mapstructure:"final_pass"`
	GuardTimeout string `mapstructure:"guard_timeout"`
	// OnError bounds the per-block guard call only. It inherits the policy's
	// on_error when unset, so the stream leg cannot be made stricter or laxer
	// by accident.
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
		s.Direction = defaultLegs
	}
	if s.OnError == "" {
		s.OnError = defaultOnError
	}
	s.Streaming.applyDefaults(s.OnError)
}

func (s *StreamingSettings) applyDefaults(onError string) {
	if s.HeadChars == 0 {
		s.HeadChars = defaultStreamingHeadChars
	}
	if s.MinCharsBetweenEvals == 0 {
		s.MinCharsBetweenEvals = defaultStreamingMinCharsBetweenEvals
	}
	if s.MaxHoldMS == 0 {
		s.MaxHoldMS = defaultStreamingMaxHoldMS
	}
	if s.MaxAccumulatedBytes == 0 {
		s.MaxAccumulatedBytes = defaultStreamingMaxAccumulatedBytes
	}
	s.GuardTimeout = strings.TrimSpace(s.GuardTimeout)
	if s.GuardTimeout == "" {
		s.GuardTimeout = defaultStreamingGuardTimeout.String()
	}
	if s.OnError == "" {
		s.OnError = onError
	}
}

func (s *Settings) validate() error {
	switch s.Direction {
	case legRequest, legResponse, legRequestResponse:
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
	return s.Streaming.validate()
}

func (s StreamingSettings) validate() error {
	if s.HeadChars < minStreamingHeadChars || s.HeadChars > maxStreamingHeadChars {
		return fmt.Errorf(
			"trustguard: streaming.head_chars must be between %d and %d, got %d",
			minStreamingHeadChars, maxStreamingHeadChars, s.HeadChars,
		)
	}
	if s.MinCharsBetweenEvals < minStreamingMinCharsBetweenEvals ||
		s.MinCharsBetweenEvals > maxStreamingMinCharsBetweenEvals {
		return fmt.Errorf(
			"trustguard: streaming.min_chars_between_evals must be between %d and %d, got %d",
			minStreamingMinCharsBetweenEvals, maxStreamingMinCharsBetweenEvals, s.MinCharsBetweenEvals,
		)
	}
	if s.MaxHoldMS < minStreamingMaxHoldMS || s.MaxHoldMS > maxStreamingMaxHoldMS {
		return fmt.Errorf(
			"trustguard: streaming.max_hold_ms must be between %d and %d, got %d",
			minStreamingMaxHoldMS, maxStreamingMaxHoldMS, s.MaxHoldMS,
		)
	}
	if s.MaxAccumulatedBytes < minStreamingMaxAccumulatedBytes ||
		s.MaxAccumulatedBytes > maxStreamingMaxAccumulatedBytes {
		return fmt.Errorf(
			"trustguard: streaming.max_accumulated_bytes must be between %d and %d, got %d",
			minStreamingMaxAccumulatedBytes, maxStreamingMaxAccumulatedBytes, s.MaxAccumulatedBytes,
		)
	}
	d, err := time.ParseDuration(s.GuardTimeout)
	if err != nil {
		return fmt.Errorf("trustguard: streaming.guard_timeout must be a duration such as 2s: %w", err)
	}
	if d < minStreamingGuardTimeout || d > maxStreamingGuardTimeout {
		return fmt.Errorf(
			"trustguard: streaming.guard_timeout must be between %s and %s, got %s",
			minStreamingGuardTimeout, maxStreamingGuardTimeout, d,
		)
	}
	switch s.OnError {
	case onErrorFailOpen, onErrorFailClosed:
	default:
		return fmt.Errorf("trustguard: streaming.on_error must be one of fail_open, fail_closed")
	}
	return nil
}

func (s StreamingSettings) finalPass() bool {
	return s.FinalPass == nil || *s.FinalPass
}

func (s StreamingSettings) guardTimeout() time.Duration {
	d, err := time.ParseDuration(s.GuardTimeout)
	if err != nil {
		return defaultStreamingGuardTimeout
	}
	return d
}

func (s StreamingSettings) failClosedOnTransport() bool {
	return s.OnError == onErrorFailClosed
}

func (s Settings) failClosedOnTransport() bool {
	return s.OnError == onErrorFailClosed
}

func (s Settings) selectsStage(stage policy.Stage) bool {
	switch s.Direction {
	case legRequest:
		return stage == policy.StagePreRequest
	case legResponse:
		return stage == policy.StagePreResponse || stage == policy.StagePostResponse
	case legRequestResponse:
		return stage == policy.StagePreRequest ||
			stage == policy.StagePreResponse ||
			stage == policy.StagePostResponse
	default:
		return false
	}
}
