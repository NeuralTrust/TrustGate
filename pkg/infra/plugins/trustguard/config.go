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
)

const (
	failureModeOpen   = "open"
	failureModeClosed = "closed"
	// defaultFailureMode is today's behaviour: a failed call lets the request through.
	defaultFailureMode = failureModeOpen
)

const (
	defaultStreamingHeadChars            = 400
	defaultStreamingMinCharsBetweenEvals = 2048
	defaultStreamingMaxHoldMS            = 800
	// maxStreamWindowBytes is the most of the accumulated text one evaluate call
	// carries. The block waits at most defaultStreamingGuardTimeout for the token
	// and the call together, so the window is fitted to that deadline and not to
	// what the detectors accept.
	maxStreamWindowBytes                = 65536
	defaultStreamingMaxAccumulatedBytes = maxStreamWindowBytes
	defaultStreamingGuardTimeout        = 2 * time.Second
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
	// FailureMode is what a request costs when TrustGuard cannot evaluate it:
	// "open" lets it through, "closed" blocks it in a mode that blocks and
	// records it in observe. It is forwarded to TrustGuard as X-Failure-Mode and
	// applied to this plugin's own failures calling it. Input failures (a body
	// TrustGuard refused for its size) are refused in both.
	FailureMode string                       `mapstructure:"failure_mode"`
	Streaming   pluginutil.StreamingSettings `mapstructure:"streaming"`
}

// streamingDefaults is the cadence of a policy that does not set its own. A
// policy whose direction includes the response inspects a streamed response
// block by block whatever its streaming block says (RUN-1661), or "Request &
// Response" would silently mean "request only" on the traffic that streams.
var streamingDefaults = pluginutil.StreamingDefaults{
	HeadChars:            defaultStreamingHeadChars,
	MinCharsBetweenEvals: defaultStreamingMinCharsBetweenEvals,
	MaxHoldMS:            defaultStreamingMaxHoldMS,
	MaxAccumulatedBytes:  defaultStreamingMaxAccumulatedBytes,
	GuardTimeout:         defaultStreamingGuardTimeout,
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
	if s.FailureMode == "" {
		s.FailureMode = defaultFailureMode
	}
	s.Streaming.ApplyDefaults(streamingDefaults)
}

// failureModeFromRaw reads failure_mode straight from a settings map that may
// not parse: it is closed only when the key (any case, as mapstructure matches
// it) is a string equal-fold to "closed", and open for everything else. It is
// used only to decide what a failure costs, so a policy that asked for closed
// does not silently fail open because some other key made its settings invalid.
// It never validates: parseConfig is still the one that rejects a bad value.
func failureModeFromRaw(settings map[string]any) string {
	for key, v := range settings {
		if !strings.EqualFold(key, "failure_mode") {
			continue
		}
		if mode, ok := v.(string); ok && strings.EqualFold(strings.TrimSpace(mode), failureModeClosed) {
			return failureModeClosed
		}
	}
	return failureModeOpen
}

// failClosed reports whether this policy refuses what TrustGuard cannot evaluate.
func (s Settings) failClosed() bool { return s.FailureMode == failureModeClosed }

func (s *Settings) validate() error {
	switch s.Direction {
	case legRequest, legResponse, legRequestResponse:
	default:
		return fmt.Errorf("trustguard: direction must be one of request, response, request_response")
	}
	switch s.FailureMode {
	case failureModeOpen, failureModeClosed:
	default:
		return fmt.Errorf("trustguard: failure_mode must be one of open, closed")
	}
	if strings.TrimSpace(s.CollectorID) == "" {
		return fmt.Errorf("trustguard: collector_id is required")
	}
	if _, err := uuid.Parse(strings.TrimSpace(s.CollectorID)); err != nil {
		return fmt.Errorf("trustguard: collector_id must be a valid UUID")
	}
	return s.Streaming.Validate(PluginName)
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

// RetiredSettings lists the settings keys this policy never stores: the plugin
// ignores them, so a stored value would read as behaviour the policy does not
// have.
// on_timeout and timeout are the TrustGuard-specific failure and deadline keys: a failed call fails open and the deadline is the deployment-wide TRUSTGUARD_TIMEOUT.
func (p *Plugin) RetiredSettings() []string {
	return []string{
		pluginutil.SettingOnError, "on_timeout", "timeout", pluginutil.SettingOnMaskFailure,
		pluginutil.SettingStreamingOnError, pluginutil.SettingStreamingGuardTimeout,
	}
}

// rawDirectionIs reports whether the unparsed settings name leg as their direction.
func rawDirectionIs(settings map[string]any, leg string) bool {
	for key, v := range settings {
		if strings.EqualFold(key, "direction") {
			d, ok := v.(string)
			return ok && d == leg
		}
	}
	return false
}
