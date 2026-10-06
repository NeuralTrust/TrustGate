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

package bedrockguardrail

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	piiActionBlock     = "block"
	piiActionAnonymize = "anonymize"
	defaultVersion     = "DRAFT"
	defaultRegion      = "us-east-1"
	defaultSessionName = "BedrockClientSession"
)

// Streaming defaults. ApplyGuardrail is a remote call against a full guardrail
// configuration rather than a single classifier, so it is slower than
// openai_moderation and the block loop calls it less often to keep the hold on
// a client's bytes bounded.
//
// Unlike google_model_armor and openai_moderation it is OPT-IN
// (streaming.enabled: true). Every block resends the whole accumulated prefix to
// ApplyGuardrail, and the on-demand quota is per account and region: 25 text
// units per second per policy type in most regions (only the largest US and
// EU regions get more), and a text unit is up to 1000 characters. A few streams
// inspected per block would throttle the customer's account, and their buffered
// requests would then fail with 502 guardrail_unavailable. Until the console
// exposes the control (RUN-1661) a policy without the key is not inspected per
// block, and the trace marks it skipped with reason streaming_disabled.
// https://docs.aws.amazon.com/general/latest/gr/bedrock.html
//
// Once a policy opts in, the stream leg fails open by default and
// MaxAccumulatedBytes is 24 KiB because ApplyGuardrail caps the input per
// policy at a number of text units (1 unit = up to 1000 characters) that
// depends on region and tier, and the smallest default is 25 units
// (eu-south-1, eu-west-3, sa-east-1 and, for content filters, the classic
// tier). Bytes are never fewer than characters, so 24576 bytes fits in 25
// units. Past it this policy is sent only the tail window, whatever window the
// rest of the stream keeps. Regions with a larger quota can raise
// streaming.max_accumulated_bytes.
// https://docs.aws.amazon.com/general/latest/gr/bedrock.html
var streamingDefaults = pluginutil.StreamingDefaults{
	HeadChars:            400,
	MinCharsBetweenEvals: 2048,
	MaxHoldMS:            800,
	MaxAccumulatedBytes:  24576,
	GuardTimeout:         2 * time.Second,
}

type Credentials struct {
	AWSRegion       string `mapstructure:"aws_region"`
	UseRole         bool   `mapstructure:"use_role"`
	RoleARN         string `mapstructure:"role_arn"`
	SessionName     string `mapstructure:"session_name"`
	AccessKeyID     string `mapstructure:"access_key_id"`     // #nosec G101 -- config field name, not a credential
	SecretAccessKey string `mapstructure:"secret_access_key"` // #nosec G101 -- config field name, not a credential
	SessionToken    string `mapstructure:"session_token"`     // #nosec G101 -- config field name, not a credential
}

type Settings struct {
	GuardrailID string      `mapstructure:"guardrail_id"`
	Version     string      `mapstructure:"version"`
	PIIAction   string      `mapstructure:"pii_action"`
	Message     string      `mapstructure:"message"`
	Credentials Credentials `mapstructure:"credentials"`
	// Streaming tunes the per-block inspection of the pre_response leg. It is off
	// when the block is absent; streaming.enabled: true turns it on.
	Streaming pluginutil.StreamingSettings `mapstructure:"streaming"`
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
	if s.Version == "" {
		s.Version = defaultVersion
	}
	if s.PIIAction == "" {
		s.PIIAction = piiActionBlock
	}
	if s.Credentials.AWSRegion == "" {
		s.Credentials.AWSRegion = defaultRegion
	}
	if s.Credentials.UseRole && s.Credentials.SessionName == "" {
		s.Credentials.SessionName = defaultSessionName
	}
	// The stream leg fails open by default whatever the buffered leg does: a
	// guardrail outage must not cut a response the client is already reading.
	// An explicit streaming.on_error: fail_closed is still honoured.
	s.Streaming.ApplyDefaults(streamingDefaults, pluginutil.StreamOnErrorFailOpen)
}

func (s *Settings) validate() error {
	if strings.TrimSpace(s.GuardrailID) == "" {
		return fmt.Errorf("bedrock_guardrail: guardrail_id is required")
	}
	switch s.PIIAction {
	case piiActionBlock, piiActionAnonymize:
	default:
		return fmt.Errorf("bedrock_guardrail: pii_action must be one of block, anonymize")
	}
	if s.Credentials.UseRole {
		if strings.TrimSpace(s.Credentials.RoleARN) == "" {
			return fmt.Errorf("bedrock_guardrail: role_arn is required when use_role is true")
		}
		return s.Streaming.Validate(PluginName)
	}
	if strings.TrimSpace(s.Credentials.AccessKeyID) == "" || strings.TrimSpace(s.Credentials.SecretAccessKey) == "" {
		return fmt.Errorf("bedrock_guardrail: access_key_id and secret_access_key are required when use_role is false")
	}
	return s.Streaming.Validate(PluginName)
}
