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

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

const (
	piiActionBlock     = "block"
	piiActionAnonymize = "anonymize"
	defaultVersion     = "DRAFT"
	defaultRegion      = "us-east-1"
	defaultSessionName = "BedrockClientSession"
)

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
		return nil
	}
	hasAccessKey := strings.TrimSpace(s.Credentials.AccessKeyID) != ""
	hasSecretKey := strings.TrimSpace(s.Credentials.SecretAccessKey) != ""
	if hasAccessKey != hasSecretKey {
		return fmt.Errorf("bedrock_guardrail: access_key_id and secret_access_key must be set together")
	}
	return nil
}
